# Code and dependencies are built and deployed by Terraform.
#   * code: src/ zipped at plan time; any change publishes new Lambda versions
#   * dependencies: a Lambda layer rebuilt only when requirements.txt, the Python version or
#     the architecture changes (needs python3 + pip + zip on the machine running Terraform)

locals {
  repo_root    = "${path.module}/.."
  src_dir      = "${local.repo_root}/src"
  build_dir    = "${path.module}/.build"
  requirements = "${local.repo_root}/requirements.txt"
  layer_zip    = "${local.build_dir}/deps-layer.zip"
  pip_platform = var.lambda_architecture == "arm64" ? "manylinux2014_aarch64" : "manylinux2014_x86_64"
  layer_hash   = base64sha256("${filesha256(local.requirements)}-${var.lambda_python_version}-${var.lambda_architecture}")
}

data "archive_file" "code" {
  type        = "zip"
  source_dir  = local.src_dir
  output_path = "${local.build_dir}/code.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc"]
}

resource "terraform_data" "deps_layer" {
  triggers_replace = [local.layer_hash]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      rm -rf "${local.build_dir}/layer" && mkdir -p "${local.build_dir}/layer/python"
      python3 -m pip install --quiet --disable-pip-version-check -r "${local.requirements}" \
        --target "${local.build_dir}/layer/python" \
        --platform ${local.pip_platform} --implementation cp \
        --python-version ${var.lambda_python_version} --only-binary=:all:
      cd "${local.build_dir}/layer" && rm -f "${abspath(local.layer_zip)}" && zip -qr "${abspath(local.layer_zip)}" python
    EOT
  }
}

resource "aws_lambda_layer_version" "deps" {
  layer_name               = "${local.name}-deps"
  filename                 = local.layer_zip
  source_code_hash         = local.layer_hash
  compatible_runtimes      = ["python${var.lambda_python_version}"]
  compatible_architectures = [var.lambda_architecture]

  depends_on = [terraform_data.deps_layer]
}

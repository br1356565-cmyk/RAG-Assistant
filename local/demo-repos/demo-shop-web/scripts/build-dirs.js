// Build-time helper only: creates output folders. Never runs in production.
const mkdirp = require("mkdirp");

for (const dir of ["dist/assets", "dist/cache"]) {
  mkdirp.sync(dir);
}
console.log("build folders ready");

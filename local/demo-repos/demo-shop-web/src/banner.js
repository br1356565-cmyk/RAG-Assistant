const _ = require("lodash");

// Compiles a marketing template supplied by the caller.
function renderBanner(templateText, data) {
  return _.template(templateText)(data);
}

module.exports = { renderBanner };

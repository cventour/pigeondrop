// CSV for the activity export. Plain script, no module: the page loads it with
// a script tag, and the tests run it in a vm without a browser.
//
// A cell that starts with = + - @ tab or CR is read by a spreadsheet as a
// formula, and logged values (file names, user agents) come from strangers, so
// those get a leading apostrophe. Then standard quoting: wrap in quotes when
// the cell holds a comma, quote or line break, and double any quote.
function csvCell(v) {
  let s = v === null || v === undefined ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
const csvRow = (cells) => cells.map(csvCell).join(',');

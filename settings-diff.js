// Which settings changed, as { field, from, to }. A field that holds a secret
// is reported as changed and nothing more: the log is readable by anyone who
// can open the page. Settings has none today; the pattern is here so that one
// added later is redacted by default rather than leaked by omission.
const SECRET_FIELD = /pass|token|key|secret|credential|auth/i;
export function settingsDiff(before, after) {
  const out = [];
  for (const group of Object.keys({ ...before, ...after })) {
    const b = before[group] || {}, a = after[group] || {};
    for (const k of Object.keys({ ...b, ...a })) {
      if (JSON.stringify(b[k]) === JSON.stringify(a[k])) continue;
      out.push(SECRET_FIELD.test(k) ? { field: `${group}.${k}`, changed: true }
                                    : { field: `${group}.${k}`, from: b[k], to: a[k] });
    }
  }
  return out;
}

// UI Action (Server-side) - Un solo RFC por usuario en ventana de 10s, con tasks sin duplicar.
(function executeAction(current, action, gs) {
  // ---------- Utilidades ----------
  function getURI() {
    try {
      if (action && action.getGlideURI) return action.getGlideURI();
      if (gs.action && gs.action.getGlideURI) return gs.action.getGlideURI();
    } catch (e) {}
    return null;
  }
  function dedupe(arr) {
    var seen = {}, out = [];
    for (var i = 0; i < arr.length; i++) {
      var v = String(arr[i] || '').trim();
      if (v && !seen[v]) { seen[v] = true; out.push(v); }
    }
    return out;
  }
  function safeGet(gr, fieldNames) {
    for (var i = 0; i < fieldNames.length; i++) {
      var f = fieldNames[i];
      if (gr.isValidField(f)) {
        var v = gr.getValue(f);
        if (v) return v;
      }
    }
    return '';
  }

  // ---------- 1) Recoger selección ----------
  var uri = getURI();
  var raw = uri ? (uri.getParameter('sysparm_checked_items') || '') : '';
  var ids = dedupe(raw.split(','));

  // Fallback: como tu vista dispara per-row, aquí suele entrar el registro "actual"
  if (ids.length === 0 && current && current.isValidRecord && current.isValidRecord()) {
    ids = [String(current.getUniqueValue())];
  }

  if (ids.length === 0) {
    gs.addErrorMessage('No se encontraron vulnerabilidades seleccionadas.');
    action.setRedirectURL(current);
    return;
  }

  // ---------- 2) Cargar vulnerabilidades de esta llamada ----------
  var vulns = [];
  var gr = new GlideRecord('sn_vul_vulnerable_item');
  gr.addQuery('sys_id', 'IN', ids.join(','));
  gr.query();
  while (gr.next()) {
    var sys_id = String(gr.getUniqueValue());
    var number = safeGet(gr, ['number']);
    var summary = safeGet(gr, ['summary', 'short_description', 'name']);
    var ci = safeGet(gr, ['cmdb_ci', 'configuration_item']);
    var ciDisp = ci ? (gr.getDisplayValue('cmdb_ci') || gr.getDisplayValue('configuration_item')) : '';
    vulns.push({ sys_id: sys_id, number: number, summary: summary, ci: ci, ciDisp: ciDisp });
  }

  if (vulns.length === 0) {
    gs.addErrorMessage('Los registros seleccionados no existen o no son accesibles.');
    action.setRedirectURL(current);
    return;
  }

  // ---------- 3) Clave de deduplicación temporal por usuario (bucket 10s) ----------
  var epochMs = parseInt(new GlideDateTime().getNumericValue(), 10);
  var bucket10s = Math.floor(epochMs / 10000); // 10.000 ms = 10s
  var corrDisplay = 'create_rfc_from_vulns';
  var corrId = gs.getUserID() + ':' + bucket10s;

  // Buscar si ya existe el RFC de este usuario en este bucket de 10s
  var cr = new GlideRecord('change_request');
  cr.addQuery('opened_by', gs.getUserID());
  cr.addQuery('correlation_display', corrDisplay);
  cr.addQuery('correlation_id', corrId);
  cr.orderByDesc('sys_created_on');
  cr.setLimit(1);
  cr.query();

  var crId = '';
  var reused = false;

  if (cr.next()) {
    crId = String(cr.getUniqueValue());
    reused = true;
  } else {
    // ---------- 4) Crear el RFC nuevo ----------
    cr.initialize();
    cr.setValue('opened_by', gs.getUserID());
    cr.setValue('type', 'normal'); // ajusta a tu proceso: 'standard' | 'normal' | 'emergency'
    cr.setValue('correlation_display', corrDisplay);
    cr.setValue('correlation_id', corrId);

    // Si todas las vulnerabilidades de ESTA llamada comparten CI, asignarlo
    var firstCI = vulns[0].ci;
    var allSameCI = !!firstCI && vulns.every(function(v){ return v.ci === firstCI; });

    cr.setValue('short_description', 'Remediación de vulnerabilidades (lote de ' + vulns.length + ')');

    var lines = [];
    lines.push('Vulnerabilidades incluidas inicialmente (' + vulns.length + '):');
    for (var i = 0; i < vulns.length; i++) {
      var v = vulns[i];
      lines.push('- ' + (v.number || v.sys_id) +
                 (v.summary ? (' | ' + v.summary) : '') +
                 (v.ciDisp ? (' | CI: ' + v.ciDisp) : ''));
    }
    cr.setValue('description', lines.join('\n'));
    if (allSameCI) cr.setValue('cmdb_ci', firstCI);

    // >>> Si tu proceso exige más campos obligatorios, complétalos aquí:
    // cr.setValue('category', 'Software');
    // cr.setValue('risk', '3 - Moderate');
    // cr.setValue('impact', '3 - Low');
    // cr.setValue('assignment_group', '<sys_id_del_grupo>');

    crId = cr.insert();
    if (!crId) {
      var err = cr.getLastErrorMessage ? cr.getLastErrorMessage() : '(sin detalle)';
      gs.addErrorMessage('No se pudo crear el RFC. Motivo: ' + err);
      action.setRedirectURL(current);
      return;
    }
    cr.get(crId); // recargar para display values
  }

  // ---------- 5) Crear Change Tasks sin duplicar (por sys_id) ----------
  var createdTasks = 0, skippedTasks = 0;

  for (var j = 0; j < vulns.length; j++) {
    var v2 = vulns[j];

    // ¿Ya existe para este RFC?
    var ctFind = new GlideRecord('change_task');
    ctFind.addQuery('change_request', crId);
    ctFind.addQuery('correlation_id', v2.sys_id);
    ctFind.setLimit(1);
    ctFind.query();

    if (ctFind.next()) {
      skippedTasks++;
      continue;
    }

    var ct = new GlideRecord('change_task');
    ct.initialize();
    ct.setValue('change_request', crId);
    ct.setValue('correlation_id', v2.sys_id); // dedupe por item
    ct.setValue('short_description', 'Remediar ' + (v2.number || v2.sys_id));

    var taskDesc = '';
    taskDesc += (v2.summary ? v2.summary + '\n' : '');
    taskDesc += 'Vulnerable Item: ' + (v2.number || v2.sys_id) + '\n';
    if (v2.ciDisp) taskDesc += 'CI: ' + v2.ciDisp + '\n';
    taskDesc += 'Registro: ' + gs.getProperty('glide.servlet.uri') + 'sn_vul_vulnerable_item.do?sys_id=' + v2.sys_id;

    ct.setValue('description', taskDesc);
    if (v2.ci) ct.setValue('cmdb_ci', v2.ci);
    ct.insert();
    createdTasks++;
  }

  // ---------- 6) (Opcional) Si se está reutilizando, documentar los nuevos ítems añadidos ----------
  if (reused && createdTasks > 0) {
    var addLines = [];
    addLines.push('');
    addLines.push('--- Nuevos ítems añadidos en esta ejecución (' + createdTasks + ') ---');
    for (var k = 0; k < vulns.length; k++) {
      var v3 = vulns[k];
      var exists = new GlideRecord('change_task');
      exists.addQuery('change_request', crId);
      exists.addQuery('correlation_id', v3.sys_id);
      exists.setLimit(1);
      exists.query();
      if (exists.next()) {
        addLines.push('- ' + (v3.number || v3.sys_id) +
                      (v3.summary ? (' | ' + v3.summary) : '') +
                      (v3.ciDisp ? (' | CI: ' + v3.ciDisp) : ''));
      }
    }
    var newDesc = (cr.getValue('description') || '') + '\n' + addLines.join('\n');
    cr.setValue('description', newDesc);
    cr.update();
  }

  gs.addInfoMessage(
    (reused ? 'RFC reutilizado: ' : 'RFC creado: ') +
    cr.getDisplayValue('number') +
    ' | Tasks creadas: ' + createdTasks +
    (skippedTasks ? (' | Tasks ya existentes: ' + skippedTasks) : '')
  );
  action.setRedirectURL(cr);

})(current, action, gs);


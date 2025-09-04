Uncaught ReferenceError: g_list is not defined
    at onClick (sn_vul_vulnerable_item_list.do:550:26)
    at sn_vul_vulnerable_item_list.do:566:1

function onClick() {
    console.log('RFC Grupal: Client Script iniciado');
    // Log en consola del navegador
    var selectedSysIds = g_list.getChecked();
// UI Action (Server-side) - Crear un RFC único con Change Tasks por vulnerabilidad seleccionada (sin duplicados)
(function executeAction(current, action, gs) {
  // --- Utilidades ---
  function getURI() {
    try {
      if (action && action.getGlideURI) return action.getGlideURI();
      if (gs.action && gs.action.getGlideURI) return gs.action.getGlideURI();
    } catch (e) {}
    return null;
  }

  function dedupe(arr) {
    var seen = {};
    var out = [];
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

  // --- Recoger selección desde la lista ---
  var uri = getURI();
  var raw = uri ? (uri.getParameter('sysparm_checked_items') || '') : '';
  var ids = dedupe(raw.split(','));

  // Fallback: si no hay selección múltiple, procesa el registro actual (si existe)
  if (ids.length === 0 && current && current.isValidRecord && current.isValidRecord()) {
    ids = [String(current.getUniqueValue())];
  }

  if (ids.length === 0) {
    gs.addErrorMessage('No se encontraron vulnerabilidades seleccionadas.');
    action.setRedirectURL(current);
    return;
  }

  // --- Cargar vulnerabilidades ---
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

  // --- Buscar si YA existe un RFC "reciente" para este usuario y esta acción ---
  // Marcamos nuestros RFC con correlation_display = 'create_rfc_from_vulns'
  // y si hay uno creado por este usuario en los últimos 60s, lo reusamos.
  var cr = new GlideRecord('change_request');
  cr.addQuery('opened_by', gs.getUserID());
  cr.addQuery('correlation_display', 'create_rfc_from_vulns');
  cr.addQuery('sys_created_on', '>=', gs.secondsAgoStart(60)); // ventana de 60s
  cr.orderByDesc('sys_created_on');
  cr.setLimit(1);
  cr.query();

  var crId = '';
  var isReuse = false;

  if (cr.next()) {
    crId = String(cr.getUniqueValue());
    isReuse = true;
  } else {
    // --- Crear un RFC nuevo ---
    cr.initialize();
    cr.setValue('type', 'normal'); // ajusta a tu proceso: 'standard' | 'normal' | 'emergency'
    cr.setValue('correlation_display', 'create_rfc_from_vulns'); // marca para deduplicación

    // Si todas las vulnerabilidades comparten el mismo CI, lo asignamos al RFC
    var firstCI = vulns[0].ci;
    var allSameCI = !!firstCI && vulns.every(function(v){ return v.ci === firstCI; });

    cr.setValue('short_description', 'Remediación de vulnerabilidades (' + vulns.length + ')');

    // Construimos la descripción inicial (puede ampliarse si luego se reusa)
    var lines = [];
    lines.push('Vulnerabilidades incluidas (' + vulns.length + '):');
    for (var i = 0; i < vulns.length; i++) {
      var v = vulns[i];
      lines.push('- ' + (v.number || v.sys_id) +
                 (v.summary ? (' | ' + v.summary) : '') +
                 (v.ciDisp ? (' | CI: ' + v.ciDisp) : ''));
    }
    cr.setValue('description', lines.join('\n'));

    if (allSameCI) cr.setValue('cmdb_ci', firstCI);

    crId = cr.insert();
    if (!crId) {
      gs.addErrorMessage('No se pudo crear el RFC.');
      action.setRedirectURL(current);
      return;
    }
    // Vuelve a cargar el objeto para posteriores actualizaciones
    cr.get(crId);
  }

  // --- Crear Change Tasks sin duplicar (1 por vulnerabilidad) ---
  // Usamos correlation_id en change_task = sys_id del vulnerable item.
  var createdTasks = 0;
  var skippedTasks = 0;

  for (var j = 0; j < vulns.length; j++) {
    var v2 = vulns[j];

    // ¿Ya existe la task con este sys_id ligada al RFC?
    var ctFind = new GlideRecord('change_task');
    ctFind.addQuery('change_request', crId);
    ctFind.addQuery('correlation_id', v2.sys_id);
    ctFind.setLimit(1);
    ctFind.query();

    if (ctFind.next()) {
      skippedTasks++;
      continue; // ya existe, no duplicar
    }

    var ct = new GlideRecord('change_task');
    ct.initialize();
    ct.setValue('change_request', crId);
    ct.setValue('correlation_id', v2.sys_id); // clave de deduplicación
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

  // --- (Opcional) Si reusamos un RFC, actualizar la descripción con los nuevos ítems añadidos ---
  if (isReuse && createdTasks > 0) {
    var addLines = [];
    addLines.push('');
    addLines.push('--- Nuevos ítems añadidos (' + createdTasks + ') ---');
    for (var k = 0; k < vulns.length; k++) {
      var v3 = vulns[k];
      // Solo documentar los que no tenían task previa
      var exists = new GlideRecord('change_task');
      exists.addQuery('change_request', crId);
      exists.addQuery('correlation_id', v3.sys_id);
      exists.setLimit(1);
      exists.query();
      if (exists.next() && exists.sys_created_on >= gs.secondsAgoStart(5)) {
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
    (isReuse ? 'RFC reutilizado: ' : 'RFC creado: ') +
    cr.getDisplayValue('number') +
    ' | Tasks creadas: ' + createdTasks +
    (skippedTasks ? (' | Tasks ya existentes: ' + skippedTasks) : '')
  );

  action.setRedirectURL(cr);
})(current, action, gs);



----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// UI Action (Server-side) - Crear un RFC único con Change Tasks por vulnerabilidades seleccionadas
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

  // ---------- Recoger selección ----------
  var uri = getURI();
  var raw = uri ? (uri.getParameter('sysparm_checked_items') || '') : '';
  var ids = dedupe(raw.split(','));

  // Fallback si se ejecuta desde un registro
  if (ids.length === 0 && current && current.isValidRecord && current.isValidRecord()) {
    ids = [String(current.getUniqueValue())];
  }

  if (ids.length === 0) {
    gs.addErrorMessage('No se encontraron vulnerabilidades seleccionadas.');
    action.setRedirectURL(current);
    return;
  }

  // Clave de lote determinista (ordenada)
  var sorted = ids.slice().sort();
  var batchKey = sorted.join(',');

  // ---------- Mutex por lote para evitar carreras ----------
  var mutex = new GlideMutex('create_rfc_from_vulns_' + gs.getUserID() + '_' + GlideStringUtil.sha1(batchKey));
  if (!mutex.lock(30000)) { // espera hasta 30s
    gs.addErrorMessage('No se pudo adquirir el bloqueo para este lote. Intenta de nuevo.');
    action.setRedirectURL(current);
    return;
  }

  try {
    // ---------- Cargar vulnerabilidades ----------
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

    // ---------- Reusar si ya existe RFC para este lote ----------
    // Usamos correlation_display = etiqueta fija y correlation_id = hash del lote
    var batchHash = GlideStringUtil.sha1(batchKey);
    var cr = new GlideRecord('change_request');
    cr.addQuery('correlation_display', 'create_rfc_from_vulns');
    cr.addQuery('correlation_id', batchHash);
    cr.setLimit(1);
    cr.query();

    var crId = '';
    if (cr.next()) {
      crId = String(cr.getUniqueValue());
    } else {
      // Crear el RFC nuevo
      cr.initialize();
      cr.setValue('type', 'normal'); // ajusta: 'standard' | 'normal' | 'emergency'
      cr.setValue('correlation_display', 'create_rfc_from_vulns');
      cr.setValue('correlation_id', batchHash);
      cr.setValue('opened_by', gs.getUserID());

      // Si todas comparten CI, usarlo en el RFC
      var firstCI = vulns[0].ci;
      var allSameCI = !!firstCI && vulns.every(function(v){ return v.ci === firstCI; });

      cr.setValue('short_description', 'Remediación de vulnerabilidades (' + vulns.length + ')');

      var lines = [];
      lines.push('Vulnerabilidades incluidas (' + vulns.length + '):');
      for (var i = 0; i < vulns.length; i++) {
        var v = vulns[i];
        lines.push('- ' + (v.number || v.sys_id) +
                   (v.summary ? (' | ' + v.summary) : '') +
                   (v.ciDisp ? (' | CI: ' + v.ciDisp) : ''));
      }
      cr.setValue('description', lines.join('\n'));

      if (allSameCI) cr.setValue('cmdb_ci', firstCI);

      crId = cr.insert();
      if (!crId) {
        gs.addErrorMessage('No se pudo crear el RFC.');
        action.setRedirectURL(current);
        return;
      }
      cr.get(crId); // recargar para display values
    }

    // ---------- Crear Change Tasks sin duplicar ----------
    // Dedupe por (change_request, correlation_id=sys_id del vulnerable item)
    var createdTasks = 0, skippedTasks = 0;

    for (var j = 0; j < vulns.length; j++) {
      var v2 = vulns[j];

      var ctFind = new GlideRecord('change_task');
      ctFind.addQuery('change_request', crId);
      ctFind.addQuery('correlation_id', v2.sys_id);
      ctFind.setLimit(1);
      ctFind.query();

      if (ctFind.next()) {
        skippedTasks++;
        continue; // ya existía para ese item
      }

      var ct = new GlideRecord('change_task');
      ct.initialize();
      ct.setValue('change_request', crId);
      ct.setValue('correlation_id', v2.sys_id);
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

    gs.addInfoMessage(
      'RFC ' + cr.getDisplayValue('number') +
      ' listo | Tasks creadas: ' + createdTasks +
      (skippedTasks ? (' | Tasks ya existentes: ' + skippedTasks) : '')
    );
    action.setRedirectURL(cr);

  } finally {
    // Liberar el bloqueo siempre
    try { mutex.unlock(); } catch (e) {}
  }
})(current, action, gs);

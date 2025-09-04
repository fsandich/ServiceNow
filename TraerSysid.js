// Client Script
function onClick() {
    var selectedSysIds = g_list.getChecked(); // Recoge los sys_id seleccionados en la lista
    if (!selectedSysIds || selectedSysIds.length === 0) {
        alert('Debes seleccionar registros.');
        return;
    }
    var ga = new GlideAjax('RFCGrupalScriptInclude');
    ga.addParam('sysparm_name', 'crearRFCGrupal');
    ga.addParam('sysparm_sysids', selectedSysIds.join(','));
    ga.getXMLAnswer(function(response) {
        var answer = response;
        alert(answer);
        // Opcional: redirige a registro, recarga página, etc.
    });
}
onClick();


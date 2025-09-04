function onClick() {
    console.log('RFC Grupal: Client Script iniciado'); // Log en consola del navegador
    var selectedSysIds = g_list.getChecked();
    console.log('RFC Grupal: SysIds seleccionados:', selectedSysIds);
    if (!selectedSysIds || selectedSysIds.length === 0) {
        alert('Debes seleccionar registros.');
        return;
    }
    var ga = new GlideAjax('RFCGrupalScriptInclude');
    console.log('RFC Grupal: GlideAjax creado');
    ga.addParam('sysparm_name', 'crearRFCGrupal');
    ga.addParam('sysparm_sysids', selectedSysIds.join(','));
    ga.getXMLAnswer(function(response) {
        console.log('RFC Grupal: Respuesta de ScriptInclude:', response);
        alert(response);
        // Opcional: window.location = ...
    });
}
onClick();


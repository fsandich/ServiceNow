function onClick() {
    console.log('RFC Grupal: Client Script iniciado');
    var selectedSysIds;
    // Intenta con list2
    if (typeof GlideList2 !== 'undefined') {
        var gr = GlideList2.get('sn_vul_vulnerable_item');
        if (gr) {
            selectedSysIds = gr.getChecked();
        }
    }
    // Intenta con list v3
    if (!selectedSysIds && typeof GlideList3 !== 'undefined') {
        var gr3 = GlideList3.get('sn_vul_vulnerable_item');
        if (gr3) {
            selectedSysIds = gr3.getChecked();
        }
    }
    if (!selectedSysIds || selectedSysIds.length === 0) {
        alert('Debes seleccionar registros.');
        return;
    }
    console.log('RFC Grupal: SysIds seleccionados:', selectedSysIds);
    var ga = new GlideAjax('RFCGrupalScriptInclude');
    ga.addParam('sysparm_name', 'crearRFCGrupal');
    ga.addParam('sysparm_sysids', selectedSysIds.join(','));
    ga.getXMLAnswer(function(response) {
        console.log('RFC Grupal: Respuesta de ScriptInclude:', response);
        alert(response);
    });
}
onClick();


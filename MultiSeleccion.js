(function pruebaMultiSeleccion() {
    gs.log('Prueba Incident: Script iniciado');
    var selectedSysIds = (typeof action !== 'undefined' && typeof action.getGlideListSelection === 'function') ? action.getGlideListSelection() : [];
    gs.log('Prueba Incident: sys_id seleccionados = ' + selectedSysIds);
    if (!selectedSysIds || selectedSysIds.length === 0) {
        gs.addErrorMessage('No se seleccionó ningún incidente.');
        return;
    }
    gs.addInfoMessage('Sys_id de incidentes seleccionados: ' + selectedSysIds.join(','));
})();

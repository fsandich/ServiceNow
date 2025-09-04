var selectedSysIds = [];
// Método estándar
if (typeof action !== 'undefined' && typeof action.getGlideListSelection === 'function') {
    selectedSysIds = action.getGlideListSelection();
}
// Si sigue vacío, prueba con sysparm_selection del query (algunas instancias lo envían)
if (!selectedSysIds || selectedSysIds.length === 0) {
    var s = gs.getParameter('sysparm_selection');
    if (s) {
        selectedSysIds = s.split(',');
    }
}
gs.log('RFC Grupal: sys_id seleccionados = ' + selectedSysIds);

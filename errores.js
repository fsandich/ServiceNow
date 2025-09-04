Uncaught ReferenceError: g_list is not defined
    at onClick (sn_vul_vulnerable_item_list.do:550:26)
    at sn_vul_vulnerable_item_list.do:566:1

function onClick() {
    console.log('RFC Grupal: Client Script iniciado');
    // Log en consola del navegador
    var selectedSysIds = g_list.getChecked();

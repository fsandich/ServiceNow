(function executeBulkRFC() {
    var selectedSysIds = gs.action.getGlideListSelection();
    if (!selectedSysIds || selectedSysIds.length == 0) {
        gs.addErrorMessage('Debes seleccionar vulnerabilidades.');
        return;
    }

    var description = 'Se realizará la remediación de las vulnerabilidades:\n';
    var origenList = [];
    for (var i = 0; i < selectedSysIds.length; i++) {
        var vulnItem = new GlideRecord('vulnerable_item');
        if (vulnItem.get(selectedSysIds[i])) {
            // Agregar el campo Number al texto
            description += vulnItem.number + '\n';

            // Obtener el nombre de la vulnerabilidad, quitar "TEN-" y agregar solo el número
            var vuln = vulnItem.vulnerability; // Referencia al registro Vulnerability
            var vulnRec = new GlideRecord('vulnerability');
            if (vulnRec.get(vuln)) {
                var name = vulnRec.name + '';
                if (name.indexOf('TEN-') === 0) {
                    name = name.replace('TEN-', '');
                }
                origenList.push(name);
            }
        }
    }

    // Crear el RFC estándar con los datos construidos
    var rfc = new GlideRecord('change_request');
    rfc.initialize();
    rfc.type = 'standard'; // Change tipo estándar
    rfc.short_description = 'RFC grupal de remediación';
    rfc.description = description;
    rfc.u_origen = origenList.join(','); // Campo personalizado con los códigos

    var newRFCId = rfc.insert();
    if (newRFCId) {
        gs.addInfoMessage('RFC creado correctamente');
        // Opcional: redirige al RFC
        gs.action.setRedirectURL('/change_request.do?sys_id=' + newRFCId);
    } else {
        gs.addErrorMessage('No se pudo crear el RFC');
    }
})();

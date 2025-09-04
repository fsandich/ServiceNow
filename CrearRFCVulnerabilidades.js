(function executeBulkRFC() {
    // Captura los sys_id seleccionados del contexto de lista
    var selectedSysIds = (typeof action !== 'undefined' && typeof action.getGlideListSelection === 'function') ? action.getGlideListSelection() : [];
    if (!selectedSysIds || selectedSysIds.length === 0) {
        gs.addErrorMessage('Debes seleccionar vulnerabilidades.');
        return;
    }

    var description = 'Se realizará la remediación de las vulnerabilidades:\n';
    var origenList = [];

    for (var i = 0; i < selectedSysIds.length; i++) {
        var vulnItem = new GlideRecord('sn_vul_vulnerable_item');
        if (vulnItem.get(selectedSysIds[i])) {
            // Agregar el número del registro ("Number") a la descripción
            description += vulnItem.number + '\n';

            // Obtener el nombre/código de la vulnerabilidad (referencia)
            // Si el campo es referencia a 'sn_vul_vulnerability', adáptalo aquí
            var vulnCode = '';
            if (vulnItem.vulnerability) {
                var vulnRec = new GlideRecord('sn_vul_vulnerability');
                if (vulnRec.get(vulnItem.vulnerability)) {
                    vulnCode = vulnRec.name + '';
                    // Quitar 'TEN-' si existe y dejar solo el número
                    if (vulnCode.indexOf('TEN-') === 0) {
                        vulnCode = vulnCode.substring(4); // Elimina los primeros 4 caracteres (TEN-)
                    }
                    origenList.push(vulnCode);
                }
            }
        }
    }

    // Crear el RFC estándar con los datos indicados
    var rfc = new GlideRecord('change_request');
    rfc.initialize();
    rfc.type = 'standard'; // RFC tipo estándar
    rfc.short_description = 'RFC grupal de remediación';
    rfc.description = description;
    rfc.u_origen = origenList.join(','); // Campo personalizado con códigos separados por coma

    var newRFCId = rfc.insert();
    if (newRFCId) {
        gs.addInfoMessage('RFC creado correctamente');
        action.setRedirectURL('/change_request.do?sys_id=' + newRFCId); // Redirección a RFC creado
    } else {
        gs.addErrorMessage('No se pudo crear el RFC');
    }
})();

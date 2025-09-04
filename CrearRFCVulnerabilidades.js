(function executeBulkRFC() {
    var selectedSysIds = (typeof action !== 'undefined' && typeof action.getGlideListSelection === 'function') ? action.getGlideListSelection() : [];
    gs.log('RFC Grupal: sys_id seleccionados = ' + selectedSysIds);

    if (!selectedSysIds || selectedSysIds.length === 0) {
        gs.addErrorMessage('Debes seleccionar vulnerabilidades.');
        gs.log('RFC Grupal: No hay vulnerabilidades seleccionadas.');
        return;
    }

    var description = 'Se realizará la remediación de las vulnerabilidades:\n';
    var origenList = [];
    var registroProcesado = false;

    for (var i = 0; i < selectedSysIds.length; i++) {
        var vulnItem = new GlideRecord('sn_vul_vulnerable_item'); // Confirma el nombre exacto de la tabla
        if (vulnItem.get(selectedSysIds[i])) {
            registroProcesado = true;
            description += vulnItem.number + '\n';

            // Obtención del código de vulnerabilidad
            if (vulnItem.vulnerability) {
                var vulnRec = new GlideRecord('sn_vul_vulnerability'); // Confirma nombre exacto
                if (vulnRec.get(vulnItem.vulnerability.toString())) {
                    var vulnCode = vulnRec.name + '';
                    if (vulnCode.indexOf('TEN-') === 0) {
                        vulnCode = vulnCode.substring(4);
                    }
                    origenList.push(vulnCode);
                } else {
                    gs.log('RFC Grupal: No se encontró vulnerabilidad ' + vulnItem.vulnerability.toString());
                }
            }
        } else {
            gs.log('RFC Grupal: No se encontró vulnerable_item ' + selectedSysIds[i]);
        }
    }

    if (!registroProcesado) {
        gs.addErrorMessage('No se pudo procesar ningún registro!');
        gs.log('RFC Grupal: Ningún registro procesado.');
        return;
    }

    // Creación del RFC
    var rfc = new GlideRecord('change_request');
    rfc.initialize();
    rfc.type = 'standard';
    rfc.short_description = 'RFC grupal de remediación';
    rfc.description = description;
    rfc.u_origen = origenList.join(','); // Campo personalizado
    var newRFCId = rfc.insert();
    gs.log('RFC Grupal: sys_id RFC creado = ' + newRFCId);

    if (newRFCId) {
        gs.addInfoMessage('RFC creado correctamente');
        action.setRedirectURL('/change_request.do?sys_id=' + newRFCId);
    } else {
        gs.addErrorMessage('No se pudo crear el RFC');
        gs.log('RFC Grupal: Error al crear RFC.');
    }
})();


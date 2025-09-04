(function executeBulkRFC() {
    gs.log('RFC Grupal: Script iniciado');
    var selectedSysIds = (typeof action !== 'undefined' && typeof action.getGlideListSelection === 'function') ? action.getGlideListSelection() : [];
    gs.log('RFC Grupal: sys_id seleccionados = ' + selectedSysIds);

    if (!selectedSysIds || selectedSysIds.length === 0) {
        gs.addErrorMessage('Debes seleccionar vulnerabilidades.');
        gs.log('RFC Grupal: No hay vulnerabilidades seleccionadas.');
        return;
    }

    var description = 'Se realizará la remediación de las vulnerabilidades:\n';
    var referenciaList = [];
    var registroProcesado = false;

    for (var i = 0; i < selectedSysIds.length; i++) {
        var vulnItem = new GlideRecord('sn_vul_vulnerable_item');
        if (vulnItem.get(selectedSysIds[i])) {
            registroProcesado = true;
            gs.log('RFC Grupal: Procesando vulnItem ' + vulnItem.number);
            description += vulnItem.number + '\n';

            // Obtener el código de vulnerabilidad de sn_vul_third_party_entry
            if (vulnItem.vulnerability) {
                var tpEntry = new GlideRecord('sn_vul_third_party_entry');
                if (tpEntry.get(vulnItem.vulnerability.toString())) {
                    var vulnCode = tpEntry.name + '';
                    gs.log('RFC Grupal: Código de vulnerabilidad antes = ' + vulnCode);
                    if (vulnCode.indexOf('TEN-') === 0) {
                        vulnCode = vulnCode.substring(4);
                    }
                    gs.log('RFC Grupal: Código de vulnerabilidad después = ' + vulnCode);
                    referenciaList.push(vulnCode);
                } else {
                    gs.log('RFC Grupal: No se encontró third_party_entry ' + vulnItem.vulnerability.toString());
                }
            }
        } else {
            gs.log('RFC Grupal: No se encontró sn_vul_vulnerable_item ' + selectedSysIds[i]);
        }
    }

    if (!registroProcesado) {
        gs.addErrorMessage('No se pudo procesar ningún registro!');
        gs.log('RFC Grupal: Ningún registro procesado.');
        return;
    }

    gs.log('RFC Grupal: Construyendo RFC...');
    var rfc = new GlideRecord('change_request');
    rfc.initialize();
    rfc.type = 'standard';
    rfc.short_description = 'RFC grupal de remediación';
    rfc.description = description;
    rfc.u_id_de_referencia = referenciaList.join(',');

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



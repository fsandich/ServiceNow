var RFCGrupalScriptInclude = Class.create();
RFCGrupalScriptInclude.prototype = Object.extendsObject(AbstractAjaxProcessor, {
    crearRFCGrupal: function() {
        gs.log('RFC Grupal: ScriptInclude iniciado'); // Log en System Log de ServiceNow
        var sysids = this.getParameter('sysparm_sysids');
        gs.log('RFC Grupal: Recibidos sysids = ' + sysids);
        if (!sysids) {
            gs.log('RFC Grupal: No se recibieron sysids');
            return 'No se recibieron sysids.';
        }
        var selectedSysIds = sysids.split(',');
        var description = 'Se realizará la remediación de las vulnerabilidades:\n';
        var referenciaList = [];
        var registroProcesado = false;

        for (var i = 0; i < selectedSysIds.length; i++) {
            gs.log('RFC Grupal: Procesando sys_id ' + selectedSysIds[i]);
            var vulnItem = new GlideRecord('sn_vul_vulnerable_item');
            if (vulnItem.get(selectedSysIds[i])) {
                registroProcesado = true;
                gs.log('RFC Grupal: Encontrado vulnItem ' + vulnItem.number);
                description += vulnItem.number + '\n';

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
                    }
                }
            }
        }
        if (!registroProcesado) {
            gs.log('RFC Grupal: Ningún registro procesado.');
            return 'No se pudo procesar ningún registro!';
        }

        gs.log('RFC Grupal: Creando RFC...');
        var rfc = new GlideRecord('change_request');
        rfc.initialize();
        rfc.type = 'standard';
        rfc.short_description = 'RFC grupal de remediación';
        rfc.description = description;
        rfc.u_id_de_referencia = referenciaList.join(',');
        var newRFCId = rfc.insert();
        gs.log('RFC Grupal: RFC creado con sys_id = ' + newRFCId);

        if (newRFCId) {
            return 'RFC creado correctamente: ' + newRFCId;
        } else {
            gs.log('RFC Grupal: Error al crear RFC.');
            return 'No se pudo crear el RFC';
        }
    }
});

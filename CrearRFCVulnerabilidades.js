var RFCGrupalScriptInclude = Class.create();
RFCGrupalScriptInclude.prototype = Object.extendsObject(AbstractAjaxProcessor, {
    crearRFCGrupal: function() {
        var sysids = this.getParameter('sysparm_sysids');
        var selectedSysIds = sysids ? sysids.split(',') : [];
        var description = 'Se realizará la remediación de las vulnerabilidades:\n';
        var referenciaList = [];
        var registroProcesado = false;
        
        for (var i = 0; i < selectedSysIds.length; i++) {
            var vulnItem = new GlideRecord('sn_vul_vulnerable_item');
            if (vulnItem.get(selectedSysIds[i])) {
                registroProcesado = true;
                description += vulnItem.number + '\n';
                if (vulnItem.vulnerability) {
                    var tpEntry = new GlideRecord('sn_vul_third_party_entry');
                    if (tpEntry.get(vulnItem.vulnerability.toString())) {
                        var vulnCode = tpEntry.name + '';
                        if (vulnCode.indexOf('TEN-') === 0) {
                            vulnCode = vulnCode.substring(4);
                        }
                        referenciaList.push(vulnCode);
                    }
                }
            }
        }
        if (!registroProcesado) return 'No se pudo procesar ningún registro!';
        
        var rfc = new GlideRecord('change_request');
        rfc.initialize();
        rfc.type = 'standard';
        rfc.short_description = 'RFC grupal de remediación';
        rfc.description = description;
        rfc.u_id_de_referencia = referenciaList.join(',');
        var newRFCId = rfc.insert();
        if (newRFCId) {
            return 'RFC creado correctamente: ' + newRFCId;
        } else {
            return 'No se pudo crear el RFC';
        }
    }
});



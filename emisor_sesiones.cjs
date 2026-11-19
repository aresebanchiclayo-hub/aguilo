'use strict';
// Prototipo de logica de servidor. NO autentica dispositivos ni emite tokens Firebase.
// Solo se ejecuta en pruebas locales; no conectar a produccion.
const crypto = require('node:crypto');
function issue({uid,roleApproved,deviceProofVerified,now=Date.now(),ttlMs=15*60*1000}) {
 if (typeof uid!=='string'||!uid.trim()) throw Error('UID_INVALIDO');
 if (!roleApproved) throw Error('ROL_NO_AUTORIZADO');
 if (!deviceProofVerified) throw Error('PRUEBA_DISPOSITIVO_NO_VERIFICADA');
 if (!Number.isSafeInteger(ttlMs)||ttlMs<=0||ttlMs>15*60*1000) throw Error('TTL_INVALIDO');
 return {sessionId:crypto.randomBytes(24).toString('base64url'),uid,estado:'activo',creadoEn:now,expiraEn:now+ttlMs};
}
function revoke(session,uid,authorizedAdmin) {
 if (!authorizedAdmin) throw Error('ADMIN_NO_AUTORIZADO');
 if (!session || session.uid!==uid) throw Error('SESION_AJENA');
 return {...session,estado:'revocado'};
}
function mayAccess(session,uid,now=Date.now()) {
 return !!session && session.uid===uid && session.estado==='activo' && session.expiraEn>now;
}
module.exports={issue,revoke,mayAccess};

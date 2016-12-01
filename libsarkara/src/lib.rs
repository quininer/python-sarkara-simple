extern crate sarkara;
#[macro_use] extern crate cpython;

use std::error::Error;
use sarkara::aead::{ AeadCipher, Ascon, General, RivGeneral };
use sarkara::stream::HC256;
use sarkara::auth::HMAC;
use sarkara::hash::Blake2b;
use cpython::{ Python, PyResult, PyErr, PyBytes, PyString };
use cpython::exc::Exception;

type HHBB = General<HC256, HMAC<Blake2b>, Blake2b>;
type HRHB = RivGeneral<HC256, HMAC<Blake2b>, Blake2b>;


macro_rules! aead {
    ( fn $enname:ident, fn $dename:ident, $ty:ident ; $py:expr, $m:expr ) => {
        fn $enname(py: Python, key: PyBytes, nonce: PyBytes, aad: PyBytes, data: PyBytes) -> PyResult<PyBytes> {
            Ok(PyBytes::new(
                py,
                &$ty::new(key.data(py))
                    .with_aad(aad.data(py))
                    .encrypt(nonce.data(py), data.data(py))
            ))
        }

        fn $dename(py: Python, key: PyBytes, nonce: PyBytes, aad: PyBytes, data: PyBytes) -> PyResult<PyBytes> {
            match $ty::new(key.data(py))
                .with_aad(aad.data(py))
                .decrypt(nonce.data(py), data.data(py))
            {
                Ok(output) => Ok(PyBytes::new(py, &output)),
                Err(err) => Err(PyErr::new::<Exception, _>(py, PyString::new(py, err.description())))
            }
        }

        try!($m.add($py, stringify!($enname), py_fn!($py, $enname(key: PyBytes, nonce: PyBytes, aad: PyBytes, data: PyBytes))));
        try!($m.add($py, stringify!($dename), py_fn!($py, $dename(key: PyBytes, nonce: PyBytes, aad: PyBytes, data: PyBytes))));
    };
}


py_module_initializer!(libsarkara, initlibsarkara, PyInit_libsarkara, |py, m| {
    try!(m.add(py, "__doc__", "Sarkara is a Post-Quantum cryptography library, but there is only some aead."));
    aead!(fn ascon_encrypt, fn ascon_decrypt, Ascon; py, m);
    aead!(fn hhbb_encrypt, fn hhbb_decrypt, HHBB; py, m);
    aead!(fn hrhb_encrypt, fn hrhb_decrypt, HRHB; py, m);
    Ok(())
});

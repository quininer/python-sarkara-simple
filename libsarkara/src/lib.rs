#![feature(try_from)]

extern crate sarkara;
#[macro_use] extern crate cpython;

use std::error::Error;
use std::convert::TryFrom;
use sarkara::aead::{ AeadCipher, Ascon, General, RivGeneral };
use sarkara::stream::HC256;
use sarkara::auth::HMAC;
use sarkara::hash::Blake2b;
use sarkara::kex::{ KeyExchange, NewHope, PrivateKey, PublicKey, Reconciliation };
use cpython::{ Python, PyResult, PyErr, PyBytes, PyString };
use cpython::exc::Exception;

type HHBB = General<HC256, HMAC<Blake2b>, Blake2b>;
type HRHB = RivGeneral<HC256, HMAC<Blake2b>, Blake2b>;


macro_rules! aead {
    ( fn $encrypt:ident, fn $decrypt:ident, $ty:ident ; $py:expr, $m:expr ) => {
        fn $encrypt(py: Python, key: PyBytes, nonce: PyBytes, aad: PyBytes, data: PyBytes) -> PyResult<PyBytes> {
            Ok(PyBytes::new(
                py,
                &$ty::new(key.data(py))
                    .with_aad(aad.data(py))
                    .encrypt(nonce.data(py), data.data(py))
            ))
        }

        fn $decrypt(py: Python, key: PyBytes, nonce: PyBytes, aad: PyBytes, data: PyBytes) -> PyResult<PyBytes> {
            match $ty::new(key.data(py))
                .with_aad(aad.data(py))
                .decrypt(nonce.data(py), data.data(py))
            {
                Ok(output) => Ok(PyBytes::new(py, &output)),
                Err(err) => Err(PyErr::new::<Exception, _>(py, PyString::new(py, err.description())))
            }
        }

        $m.add($py, stringify!($encrypt), py_fn!($py, $encrypt(key: PyBytes, nonce: PyBytes, aad: PyBytes, data: PyBytes)))?;
        $m.add($py, stringify!($decrypt), py_fn!($py, $decrypt(key: PyBytes, nonce: PyBytes, aad: PyBytes, data: PyBytes)))?;
    };
}

macro_rules! kex {
    ( fn $keygen:ident, fn $exchange:ident, fn $exchange_from:ident, $ty:ident ; $py:expr, $m:expr ) => {
        fn $keygen(py: Python) -> PyResult<(PyBytes, PyBytes)> {
            let (sk, pk) = $ty::keygen();
            let sk: Vec<u8> = sk.into();
            let pk: Vec<u8> = pk.into();
            Ok((PyBytes::new(py, &sk), PyBytes::new(py, &pk)))
        }

        fn $exchange(py: Python, pk: PyBytes) -> PyResult<(PyBytes, PyBytes)> {
            let pk = PublicKey::try_from(pk.data(py))
                .map_err(|err| PyErr::new::<Exception, _>(py, PyString::new(py, err.description())))?;
            let mut output = vec![0; 32];
            let rec: Vec<u8> = $ty::exchange(&mut output, &pk).into();
            Ok((PyBytes::new(py, &output), PyBytes::new(py, &rec)))
        }

        fn $exchange_from(py: Python, sk: PyBytes, rec: PyBytes) -> PyResult<PyBytes> {
            let sk = PrivateKey::try_from(sk.data(py))
                .map_err(|err| PyErr::new::<Exception, _>(py, PyString::new(py, err.description())))?;
            let rec = Reconciliation::try_from(rec.data(py))
                .map_err(|err| PyErr::new::<Exception, _>(py, PyString::new(py, err.description())))?;
            let mut output = vec![0; 32];
            $ty::exchange_from(&mut output, &sk, &rec);
            Ok(PyBytes::new(py, &output))
        }

        $m.add($py, stringify!($keygen), py_fn!($py, $keygen()))?;
        $m.add($py, stringify!($exchange), py_fn!($py, $exchange(pk: PyBytes)))?;
        $m.add($py, stringify!($exchange_from), py_fn!($py, $exchange_from(sk: PyBytes, rec: PyBytes)))?;
    }
}


py_module_initializer!(libsarkara, initlibsarkara, PyInit_libsarkara, |py, m| {
    m.add(py, "__doc__", "Sarkara is a Post-Quantum cryptography library.")?;

    aead!(fn ascon_encrypt, fn ascon_decrypt, Ascon; py, m);
    aead!(fn hhbb_encrypt, fn hhbb_decrypt, HHBB; py, m);
    aead!(fn hrhb_encrypt, fn hrhb_decrypt, HRHB; py, m);

    kex!(fn newhope_keygen, fn newhope_exchange, fn newhope_exchange_from, NewHope; py, m);

    Ok(())
});

#![feature(try_from)]

extern crate sarkara;
#[macro_use] extern crate cpython;


#[allow(non_upper_case_globals)]
mod exc {
    py_exception!(libsarkara, CryptoException);
}

use std::error::Error;
use std::convert::TryFrom;
use sarkara::aead::{ AeadCipher, Ascon, General, RivGeneral };
use sarkara::stream::HC256;
use sarkara::auth::{ Mac, NonceMac, HMAC };
use sarkara::hash::{ Hash, GenericHash, Blake2b };
use sarkara::kex::{ KeyExchange, NewHope };
use sarkara::sign::{ Signature, Bliss };
use sarkara::pwhash::{ KeyDerive, KeyVerify, Argon2i };
use cpython::{ PythonObject, Python, PyResult, PyErr, PyBytes, PyString, PyInt };
use exc::CryptoException;

type BHMAC = HMAC<Blake2b>;
type HHBB = General<HC256, BHMAC, Blake2b>;
type HRHB = RivGeneral<HC256, BHMAC, Blake2b>;

include!("macros.rs");


py_module_initializer!(libsarkara, initlibsarkara, PyInit_libsarkara, |py, m| {
    m.add(py, "__doc__", "Sarkara is a Post-Quantum cryptography library.")?;
    m.add(py, "CryptoException", py.get_type::<CryptoException>())?;

    aead!(fn ascon_encrypt, fn ascon_decrypt, Ascon; py, m);
    aead!(fn hhbb_encrypt, fn hhbb_decrypt, HHBB; py, m);
    aead!(fn hrhb_encrypt, fn hrhb_decrypt, HRHB; py, m);

    kex!(fn newhope_keygen, fn newhope_exchange, fn newhope_exchange_from, NewHope; py, m);

    sign!(fn bliss_keygen, fn bliss_sign, fn bliss_verify, Bliss; py, m);

    pwhash!(fn argon2i_derive, fn argon2i_verify, Argon2i; py, m);

    auth!(fn bhmac_result, fn bhmac_verify, BHMAC; py, m);

    hash!(fn blake2b_hash, Blake2b; py, m);

    Ok(())
});

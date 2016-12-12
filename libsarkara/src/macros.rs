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
                Err(err) => Err(PyErr::new::<CryptoException, _>(py, PyString::new(py, err.description())))
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

        fn $exchange(py: Python, pk: PyBytes, len: PyInt) -> PyResult<(PyBytes, PyBytes)> {
            let pk = <$ty as KeyExchange>::PublicKey::try_from(pk.data(py))
                .map_err(|err| PyErr::new::<CryptoException, _>(py, PyString::new(py, err.description())))?;
            let mut output = vec![0; len.into_object().extract::<usize>(py)?];
            let rec: Vec<u8> = $ty::exchange(&mut output, &pk).into();
            Ok((PyBytes::new(py, &output), PyBytes::new(py, &rec)))
        }

        fn $exchange_from(py: Python, sk: PyBytes, rec: PyBytes, len: PyInt) -> PyResult<PyBytes> {
            let sk = <$ty as KeyExchange>::PrivateKey::try_from(sk.data(py))
                .map_err(|err| PyErr::new::<CryptoException, _>(py, PyString::new(py, err.description())))?;
            let rec = <$ty as KeyExchange>::Reconciliation::try_from(rec.data(py))
                .map_err(|err| PyErr::new::<CryptoException, _>(py, PyString::new(py, err.description())))?;
            let mut output = vec![0; len.into_object().extract::<usize>(py)?];
            $ty::exchange_from(&mut output, &sk, &rec);
            Ok(PyBytes::new(py, &output))
        }

        $m.add($py, stringify!($keygen), py_fn!($py, $keygen()))?;
        $m.add($py, stringify!($exchange), py_fn!($py, $exchange(pk: PyBytes, len: PyInt)))?;
        $m.add($py, stringify!($exchange_from), py_fn!($py, $exchange_from(sk: PyBytes, rec: PyBytes, len: PyInt)))?;
    }
}

macro_rules! sign {
    ( fn $keygen:ident, fn $sign:ident, fn $verify:ident, $ty:ident ; $py:expr, $m:expr ) => {
        fn $keygen(py: Python) -> PyResult<(PyBytes, PyBytes)> {
            let (sk, pk) = $ty::keygen();
            let sk: Vec<u8> = sk.into();
            let pk: Vec<u8> = pk.into();
            Ok((PyBytes::new(py, &sk), PyBytes::new(py, &pk)))
        }

        fn $sign(py: Python, sk: PyBytes, data: PyBytes) -> PyResult<PyBytes> {
            let sk = <$ty as Signature>::PrivateKey::try_from(sk.data(py))
                .map_err(|err| PyErr::new::<CryptoException, _>(py, PyString::new(py, err.description())))?;
            let signdata: Vec<u8> = $ty::signature(&sk, data.data(py)).into();
            Ok(PyBytes::new(py, &signdata))
        }

        fn $verify(py: Python, pk: PyBytes, signdata: PyBytes, data: PyBytes) -> PyResult<bool> {
            let pk = <$ty as Signature>::PublicKey::try_from(pk.data(py))
                .map_err(|err| PyErr::new::<CryptoException, _>(py, PyString::new(py, err.description())))?;
            let signdata = <$ty as Signature>::Signature::try_from(signdata.data(py))
                .map_err(|err| PyErr::new::<CryptoException, _>(py, PyString::new(py, err.description())))?;
            Ok($ty::verify(&pk, &signdata, data.data(py)))
        }

        $m.add($py, stringify!($keygen), py_fn!($py, $keygen()))?;
        $m.add($py, stringify!($sign), py_fn!($py, $sign(sk: PyBytes, data: PyBytes)))?;
        $m.add($py, stringify!($verify), py_fn!($py, $verify(pk: PyBytes, signdata: PyBytes, data: PyBytes)))?;
    }
}

macro_rules! pwhash {
    ( fn $derive:ident, fn $verify:ident, $ty:ident ; $py:expr, $m:expr ) => {
        fn $derive(py: Python, key: PyBytes, aad: PyBytes, salt: PyBytes, password: PyBytes, len: PyInt) -> PyResult<PyBytes> {
            $ty::default()
                .with_key(key.data(py))
                .with_aad(aad.data(py))
                .with_size(len.into_object().extract::<usize>(py)?)
                .derive::<Vec<u8>>(password.data(py), salt.data(py))
                .map(|output| PyBytes::new(py, &output))
                .map_err(|err| PyErr::new::<CryptoException, _>(py, PyString::new(py, err.description())))
        }

        fn $verify(py: Python, key: PyBytes, aad: PyBytes, salt: PyBytes, password: PyBytes, hash: PyBytes) -> PyResult<bool> {
            let hash = hash.data(py);
            $ty::default()
                .with_key(key.data(py))
                .with_aad(aad.data(py))
                .with_size(hash.len())
                .verify(password.data(py), salt.data(py), hash)
                .map_err(|err| PyErr::new::<CryptoException, _>(py, PyString::new(py, err.description())))
        }

        $m.add($py, stringify!($derive), py_fn!($py, $derive(key: PyBytes, aad: PyBytes, salt: PyBytes, password: PyBytes, len: PyInt)))?;
        $m.add($py, stringify!($verify), py_fn!($py, $verify(key: PyBytes, aad: PyBytes, salt: PyBytes, password: PyBytes, hash: PyBytes)))?;
    }
}

macro_rules! auth {
    ( fn $result:ident, fn $verify:ident, $ty:ident ; $py:expr, $m:expr ) => {
        fn $result(py: Python, key: PyBytes, nonce: PyBytes, data: PyBytes, len: PyInt) -> PyResult<PyBytes> {
            Ok(PyBytes::new(
                py,
                &$ty::new(key.data(py))
                    .with_nonce(nonce.data(py))
                    .with_size(len.into_object().extract::<usize>(py)?)
                    .result::<Vec<u8>>(data.data(py))
            ))
        }

        fn $verify(py: Python, key: PyBytes, nonce: PyBytes, data: PyBytes, tag: PyBytes) -> PyResult<bool> {
            let tag = tag.data(py);
            Ok(
                $ty::new(key.data(py))
                    .with_nonce(nonce.data(py))
                    .with_size(tag.len())
                    .verify(data.data(py), tag)
            )
        }

        $m.add($py, stringify!($result), py_fn!($py, $result(key: PyBytes, nonce: PyBytes, data: PyBytes, len: PyInt)))?;
        $m.add($py, stringify!($verify), py_fn!($py, $verify(key: PyBytes, nonce: PyBytes, data: PyBytes, tag: PyBytes)))?;
    }
}

macro_rules! hash {
    ( fn $hash:ident, $ty:ident ; $py:expr, $m:expr ) => {
        fn $hash(py: Python, key: PyBytes, data: PyBytes, len: PyInt) -> PyResult<PyBytes> {
            Ok(PyBytes::new(
                py,
                &$ty::default()
                    .with_key(key.data(py))
                    .with_size(len.into_object().extract::<usize>(py)?)
                    .hash::<Vec<u8>>(data.data(py))
            ))
        }

        $m.add($py, stringify!($hash), py_fn!($py, $hash(key: PyBytes, data: PyBytes, len: PyInt)))?;
    }
}

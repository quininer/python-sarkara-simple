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
            let pk = <$ty as KeyExchange>::PublicKey::try_from(pk.data(py))
                .map_err(|err| PyErr::new::<Exception, _>(py, PyString::new(py, err.description())))?;
            let mut output = vec![0; 32];
            let rec: Vec<u8> = $ty::exchange(&mut output, &pk).into();
            Ok((PyBytes::new(py, &output), PyBytes::new(py, &rec)))
        }

        fn $exchange_from(py: Python, sk: PyBytes, rec: PyBytes) -> PyResult<PyBytes> {
            let sk = <$ty as KeyExchange>::PrivateKey::try_from(sk.data(py))
                .map_err(|err| PyErr::new::<Exception, _>(py, PyString::new(py, err.description())))?;
            let rec = <$ty as KeyExchange>::Reconciliation::try_from(rec.data(py))
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
                .map_err(|err| PyErr::new::<Exception, _>(py, PyString::new(py, err.description())))?;
            let signdata: Vec<u8> = $ty::signature(&sk, data.data(py)).into();
            Ok(PyBytes::new(py, &signdata))
        }

        fn $verify(py: Python, pk: PyBytes, signdata: PyBytes, data: PyBytes) -> PyResult<bool> {
            let pk = <$ty as Signature>::PublicKey::try_from(pk.data(py))
                .map_err(|err| PyErr::new::<Exception, _>(py, PyString::new(py, err.description())))?;
            let signdata = <$ty as Signature>::Signature::try_from(signdata.data(py))
                .map_err(|err| PyErr::new::<Exception, _>(py, PyString::new(py, err.description())))?;
            Ok($ty::verify(&pk, &signdata, data.data(py)))
        }

        $m.add($py, stringify!($keygen), py_fn!($py, $keygen()))?;
        $m.add($py, stringify!($sign), py_fn!($py, $sign(sk: PyBytes, data: PyBytes)))?;
        $m.add($py, stringify!($verify), py_fn!($py, $verify(pk: PyBytes, signdata: PyBytes, data: PyBytes)))?;
    }
}

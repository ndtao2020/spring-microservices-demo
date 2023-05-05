## Generate an SSL certificate in a keystore

Let's open our Terminal prompt and write the following command to create a JKS keystore:

```shell
keytool -genkeypair -alias springboot -keyalg RSA -keysize 4096 -storetype JKS -keystore springboot.jks -validity 3650 -storepass password
```

To create a PKCS12 keystore, and we should, the command is the following:

```shell
keytool -genkeypair -alias springboot -keyalg RSA -keysize 4096 -storetype PKCS12 -keystore springboot.p12 -validity 3650 -storepass password
```

Let's have a closer look at the command we just run:

- genkeypair: generates a key pair;
- alias: the alias name for the item we are generating;
- keyalg: the cryptographic algorithm to generate the key pair;
- keysize: the size of the key;
- storetype: the type of keystore;
- keystore: the name of the keystore;
- validity: validity number of days;
- storepass: a password for the keystore.

If you set up a remote config repository for config client applications, it might contain an application.yml similar to
the following:

```yml
spring:
  datasource:
    username: dbuser
    password: '{cipher}FKSAJDFGYOS8F7GLHAKERGFHLSAJ'
```

The server also exposes /encrypt and /decrypt endpoints (on the assumption that these are secured and only accessed by
authorized agents). If you edit a remote config file, you can use the Config Server to encrypt values by POSTing to the
/encrypt endpoint, as shown in the following example:

```shell
$ curl localhost:8888/encrypt -s -d mysecret
682bc583f4641835fa2db009355293665d2647dade3375c0ee201de2a49f7bda
```

The inverse operation is also available through /decrypt (provided the server is configured with a symmetric key or a
full key pair), as shown in the following example:

```shell
$ curl localhost:8888/decrypt -s -d 682bc583f4641835fa2db009355293665d2647dade3375c0ee201de2a49f7bda
mysecret
```

The spring command line client (with Spring Cloud CLI extensions installed) can also be used to encrypt and decrypt, as
shown in the following example:

```shell
$ spring encrypt mysecret --key foo
682bc583f4641835fa2db009355293665d2647dade3375c0ee201de2a49f7bda
$ spring decrypt --key foo 682bc583f4641835fa2db009355293665d2647dade3375c0ee201de2a49f7bda
mysecret
```

To use a key in a file (such as an RSA public key for encryption), prepend the key value with "@" and provide the file
path, as shown in the following example:

```shell
$ spring encrypt mysecret --key @${HOME}/.ssh/id_rsa.pub
AQAjPgt3eFZQXwt8tsHAVv/QHiY5sI2dRcR+...
```

The --key argument is mandatory (despite having a -- prefix).

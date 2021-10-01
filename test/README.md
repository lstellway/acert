# Test a Certificate with Docker + NGINX

This is an example of how to build and use a certificate with NGINX via Docker.

<br />

**Prerequisites**

-   Ensure you have [Docker](https://www.docker.com/) installed and running on your system.
-   Ensure you have `sudo` privileges on the system
    -   `sudo` permissions may be required to trust certificates and edit hosts.

<br />

**Steps**

Clone the repository locally so you have access to the testing files.

```sh
git clone https://github.com/lstellway/acert.git
```

Navigate to the repository's `/test` directory.

```sh
cd ./acert/test
```

Build and trust a certificate authority _(may prompt for password)_

```sh
acert authority -trust -san 'acert-local-root'
```

Build and sign a client certificate using the host name "test.local"

```sh
acert client -parent acert-local-root.ca.cert.pem -key acert-local-root.ca.key.pem -san 'test.local,*.test.local'
```

Append an entry for "test.local" in your hosts file

```sh
sudo -- sh -c -e "printf '\n127.0.0.1 test.local' >> /etc/hosts"
```

Run the `nginx` service defined in the [`docker-compose.yml`](./docker-compose.yml)

```sh
docker-compose up -d
```

Restart your browser to ensure the new certificate authority is recognized and navigate to [https://test.local](https://test.local) in your browser.

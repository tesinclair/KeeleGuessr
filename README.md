# KeeleGuesser26

KeeleGuesser26 is available to be played [HERE](https://keeleguesser.beer)

## Docker

KeeleGuesser26 is also available as a docker image now.

You can find a [template here](https://github.com/tesinclair/KeeleGuessr/blob/master/docker-compose.yml).

Just add your own secret. A secure hex secret can be generated using `openssl rand -hex [string-length]`.
If you want to run the server in debug mode, then you should set `APP_ENV=local`, and `FLASK_DEBUG=1`.
And add
```yaml
services:
    keeleguesser:
        command: python app.py
        # Rest of config
    
```

#### New Features:
- Dockerised. Now you can pull blyk/keeleguesser:latest for AMD64 and ARM64 to run the server yourself.
- Bug fixes:
    - No longer see None when no photos are available
    - 






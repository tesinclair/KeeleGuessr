# KeeleGuesser26

KeeleGuesser26 is available to be played [HERE](https://keeleguesser.beer)

## Docker

KeeleGuesser26 is also available as a docker image now.

You can find a [template here](https://github.com/tesinclair/KeeleGuessr/blob/master/docker-compose.yml).

1. Set the Border Coords:
Then, using google maps, or something similar, you should find the coordinates of the top left corner
and bottom right corner such that the box they make make the outer bounds of your area. That is,
think of it as a border which stops the user from scrolling outside of that box. and put them in
`BORDER_COORDS` in the format given. 
2. Create a secret:
You should then add your own secret. A secure hex secret can 
be generated using `openssl rand -hex [string-length]`.
3. Finally, fill out the rest of the template as per the instructions given there.

You should then create an admin account. This can be done with the CLI-tool command:
`docker compose run --rm keeleguesser flask create-admin`. Fill in the prompts.
If you ever wish to create a second admin, you will need to provide the credentials 
of the first admin.

Finally, you can run the server with `docker compose up -d`.

### Debug Mode

If you want to run the server in debug mode, then you should set `APP_ENV=local`, and `FLASK_DEBUG=1`.
And add
```yaml
services:
    keeleguesser:
        command: python app.py
        # Rest of config
    
```

#### New Features:
- Dockerised. Now you can pull blyk/keeleguesser:latest for AMD64 and ARM64 to run the server yourself with your own photos.
- Bug fixes:
    - No longer see None when no photos are available
    - 






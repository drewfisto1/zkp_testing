### How to run
**Make sure Docker is installed** 

[https://docs.docker.com/engine/install/](url)

- Generate a JWT token
- First create a .env file
- ```touch .env```
- Then place this on the first line JWT__SECRET="{your_secret}"
- Start the containers
- ```docker compose up -d```
- visit localhost in the browser
- enter in any username (it is not being used for anything at the moment other than token generation)
- The password is 1234
  

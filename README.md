# chirpy
Une api qui parodie twitter avec différents endpoint pour un cours avec [Boot.dev](https://www.boot.dev/).
Le projet m'a permit d'apprendre sur :
  - Les requêtes et les réponses Http
  - Les Jwt
  - L'authentification vs l'authorisation
  - Pour l'avenir, je dois développer davantage avec des tests

```
go build -o out && ./out &
```
Pour revenir au process 
```
fg 
```
Voici un exemple de .env
```
JWT_SECRET=yft4H7eKQ8e2ozwR8Ek74uudXPpFz15I2qeZF3b6c+OipdRlExAy6ZjysBsKUOkoGRIgbJUDSGxqu/ZgchJNpnw==
POLKA_KEY=f271c81ff7084ee5b99a5091b42d486e
```
Script WIP

```
curl -X POST -H "Content-Type: application/json" -d '{"email": "walt@breakingbad.com", "password": "123456"}' http://localhost:8080/api/users
```

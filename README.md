# TP3 – API REST sécurisée (Spring Boot 3.3 / Java 17)

## Prérequis (Crostini / Debian)
    sudo apt update && sudo apt install -y openjdk-17-jdk maven

## Lancer les tests
    mvn test
(les tests utilisent leurs propres valeurs factices dans src/test/resources : aucune variable d'environnement requise)

## Lancer l'API (les deux variables sont OBLIGATOIRES, sinon l'API refuse de démarrer)
    export JWT_SECRET='un-secret-aleatoire-d-au-moins-32-octets-xxxxx'
    export DEMO_PASSWORD='MotDePasseDeDemo#2026'
    mvn spring-boot:run

## Essais avec curl
    # 1) Anonyme -> 401
    curl -i localhost:8080/notes

    # 2) Login (alice, bob = USER ; admin = ADMIN)
    TOKEN=$(curl -s -X POST localhost:8080/auth/login -H 'Content-Type: application/json' \
      -d '{"username":"alice","password":"'"$DEMO_PASSWORD"'"}' | sed -E 's/.*"accessToken":"([^"]+)".*/\1/')

    # 3) Créer / lire sa note
    curl -i -X POST localhost:8080/notes -H "Authorization: Bearer $TOKEN" \
      -H 'Content-Type: application/json' -d '{"title":"Hello","content":"Premier test"}'
    curl -i localhost:8080/notes/1 -H "Authorization: Bearer $TOKEN"

    # 4) Validation -> 400
    curl -i -X POST localhost:8080/notes -H "Authorization: Bearer $TOKEN" \
      -H 'Content-Type: application/json' -d '{"title":"","content":"x"}'

    # 5) USER qui supprime -> 403
    curl -i -X DELETE localhost:8080/notes/1 -H "Authorization: Bearer $TOKEN"

    # 6) Limitation de débit : 6 logins ratés d'affilée -> 429
    for i in $(seq 1 6); do curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8080/auth/login \
      -H 'Content-Type: application/json' -d '{"username":"alice","password":"faux"}'; done

## Livrable Git
    git init && git add . && git commit -m "TP3: API REST sécurisée (JWT, rôles, anti-BOLA, DTO, rate limit, tests)"

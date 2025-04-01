<?php

namespace App\Controller;

use Slim\Views\Twig;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

class AuthController
{
    private Twig $twig;

    public function __construct(Twig $twig)
    {
        $this->twig = $twig;
    }

    public function loginForm(Request $request, Response $response): Response
    {
        return $this->twig->render($response, 'login.twig');
    }

    public function registerForm(Request $request, Response $response): Response
    {
        return $this->twig->render($response, 'register.twig');
    }

    public function register(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();

        $organizationName = trim($data['organisation'] ?? '');
        $lastName = trim($data['nom'] ?? '');
        $firstName = trim($data['prenom'] ?? '');
        $email = trim($data['email'] ?? '');
        $password = trim($data['mdp'] ?? '');

        if (!$organizationName || !$lastName || !$firstName || !$email || !$password) {
            return $this->twig->render($response, 'register.twig', [
                'error' => 'Tous les champs sont requis.'
            ]);
        }

        $pdo = new \PDO(
            "mysql:host={$_ENV['DB_HOST']};port=3306;dbname={$_ENV['DB_NAME']};charset=utf8mb4",
            $_ENV['DB_USER'],
            $_ENV['DB_PASS']
        );

        // Création de l'organisation
        $stmtOrg = $pdo->prepare("INSERT INTO organizations (name, description) VALUES (:name, '')");
        $stmtOrg->execute(['name' => $organizationName]);
        $orgId = $pdo->lastInsertId();

        // Hachage du mot de passe et génération du token
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $token = bin2hex(random_bytes(25)); // 50 caractères
        $role = 0; // 0 = admin

        // Insertion dans users
        $stmtUser = $pdo->prepare("
            INSERT INTO users (token, mail, password, name, last_name, role, id_organization)
            VALUES (:token, :mail, :password, :name, :last_name, :role, :id_organization)
        ");

        $stmtUser->execute([
            'token' => $token,
            'mail' => $email,
            'password' => $hashedPassword,
            'name' => $firstName,
            'last_name' => $lastName,
            'role' => $role,
            'id_organization' => $orgId
        ]);

        // Stocker le token dans la session
        $_SESSION['token'] = $token;

        return $response->withHeader('Location', '/home')->withStatus(302);
    }

    public function login(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();
        $email = $data['email'] ?? '';
        $password = $data['mdp'] ?? '';

        $pdo = new \PDO(
            "mysql:host={$_ENV['DB_HOST']};port=3306;dbname={$_ENV['DB_NAME']};charset=utf8mb4",
            $_ENV['DB_USER'],
            $_ENV['DB_PASS']
        );

        $stmt = $pdo->prepare("SELECT * FROM users WHERE mail = :email");
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            // Authentification réussie, stocker le token
            $_SESSION['token'] = $user['token'];

            return $response->withHeader('Location', '/home')->withStatus(302);
        }

        return $this->twig->render($response, 'login.twig', [
            'error' => 'Identifiants incorrects.'
        ]);
    }
}

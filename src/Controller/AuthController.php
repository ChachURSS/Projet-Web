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
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $data = $request->getParsedBody();

        $organizationName = trim($data['organisation'] ?? '');
        $lastName = trim($data['nom'] ?? '');
        $firstName = trim($data['prenom'] ?? '');
        $email = trim($data['email'] ?? '');
        $password = trim($data['mdp'] ?? '');

        if (!$organizationName || !$lastName || !$firstName || !$email || !$password) {
            $_SESSION['flash_error_register'] = 'Tous les champs sont requis.';
            return $response->withHeader('Location', '/register')->withStatus(302);
        }

        $pdo = new \PDO(
            "mysql:host={$_ENV['DB_HOST']};port=3306;dbname={$_ENV['DB_NAME']};charset=utf8mb4",
            $_ENV['DB_USER'],
            $_ENV['DB_PASS']
        );

        try {
            $stmtOrg = $pdo->prepare("INSERT INTO organizations (name, description) VALUES (:name, '')");
            $stmtOrg->execute(['name' => $organizationName]);
            $orgId = $pdo->lastInsertId();

            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
            $token = bin2hex(random_bytes(25));
            $role = 0;

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

            $_SESSION['flash_success_login'] = "Compte créé avec succès. Connectez-vous.";
            return $response->withHeader('Location', '/login')->withStatus(302);

        } catch (\PDOException $e) {
            if ($e->getCode() === '23000') {
                $_SESSION['flash_error_register'] = "Cette adresse email est déjà utilisée.";
            } else {
                $_SESSION['flash_error_register'] = "Une erreur est survenue. Veuillez réessayer.";
            }

            return $response->withHeader('Location', '/register')->withStatus(302);
        }
    }

    public function login(Request $request, Response $response): Response
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $data = $request->getParsedBody();
        $email = $data['email'] ?? '';
        $password = $data['mdp'] ?? '';

        if (!$email || !$password) {
            $_SESSION['flash_error_login'] = 'Tous les champs sont requis.';
            return $response->withHeader('Location', '/login')->withStatus(302);
        }

        $pdo = new \PDO(
            "mysql:host={$_ENV['DB_HOST']};port=3306;dbname={$_ENV['DB_NAME']};charset=utf8mb4",
            $_ENV['DB_USER'],
            $_ENV['DB_PASS']
        );

        $stmt = $pdo->prepare("SELECT * FROM users WHERE mail = :email");
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['token'] = $user['token'];

            return $response->withHeader('Location', '/home')->withStatus(302);
        }

        $_SESSION['flash_error_login'] = "Identifiants incorrects.";
        return $response->withHeader('Location', '/login')->withStatus(302);
    }
}

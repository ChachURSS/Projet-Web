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

        $organisationName = trim($data['organisation'] ?? '');
        $nom = trim($data['nom'] ?? '');
        $prenom = trim($data['prenom'] ?? '');
        $email = trim($data['email'] ?? '');
        $mdp = trim($data['mdp'] ?? '');

        if (!$organisationName || !$nom || !$prenom || !$email || !$mdp) {
            return $this->twig->render($response, 'register.twig', [
                'error' => 'Tous les champs sont requis.'
            ]);
        }

        $pdo = new \PDO(
            "mysql:host={$_ENV['DB_HOST']};dbname={$_ENV['DB_NAME']};charset=utf8mb4",
            $_ENV['DB_USER'],
            $_ENV['DB_PASS']
        );

        $stmtOrg = $pdo->prepare("INSERT INTO organisation (nom, date_creation) VALUES (:nom, NOW())");
        $stmtOrg->execute(['nom' => $organisationName]);
        $organisationId = $pdo->lastInsertId();

        $hashedPassword = password_hash($mdp, PASSWORD_DEFAULT);

        $stmtAdmin = $pdo->prepare("
            INSERT INTO admins (mail, mdp, nom, prenom, id_organisation)
            VALUES (:mail, :mdp, :nom, :prenom, :id_organisation)
        ");
        $stmtAdmin->execute([
            'mail' => $email,
            'mdp' => $hashedPassword,
            'nom' => $nom,
            'prenom' => $prenom,
            'id_organisation' => $organisationId
        ]);

        return $response->withHeader('Location', '/login')->withStatus(302);
    }

    public function login(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();
        $email = $data['email'] ?? '';
        $password = $data['mdp'] ?? '';

        $pdo = new \PDO(
            "mysql:host={$_ENV['DB_HOST']};dbname={$_ENV['DB_NAME']};charset=utf8mb4",
            $_ENV['DB_USER'],
            $_ENV['DB_PASS']
        );

        $user = null;
        $statut = null;

        $tables = [
            'admins' => 'id_admin',
            'pilotes' => 'id_pilote',
            'eleves' => 'id_eleve',
        ];

        foreach ($tables as $table => $idColumn) {
            $stmt = $pdo->prepare("SELECT * FROM $table WHERE mail = :email");
            $stmt->execute(['email' => $email]);
            $result = $stmt->fetch();

            if ($result && password_verify($password, $result['mdp'])) {
                $user = $result;
                $statut = rtrim($table, 's');
                break;
            }
        }

        if ($user) {
            $_SESSION['user'] = [
                'id' => $user[$idColumn],
                'nom' => $user['nom'],
                'prenom' => $user['prenom'],
                'email' => $user['mail'],
                'statut' => $statut,
                'id_organisation' => $user['id_organisation'] ?? null,
            ];

            return $response
                ->withHeader('Location', '/')
                ->withStatus(302);
        }

        return $this->twig->render($response, 'login.twig', [
            'error' => 'Email ou mot de passe incorrect.'
        ]);
    }

}

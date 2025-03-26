<?php

use Slim\App;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\Twig;
use App\Controller\StageController;
use App\Controller\AuthController;

return function (App $app) {
    $app->get('/', function (Request $request, Response $response, $args) {
        $view = Twig::fromRequest($request);
        return $view->render($response, 'home.twig');
    });

    $app->get('/test', function (Request $request, Response $response, $args) {
        $response->getBody()->write("Slim fonctionne !");
        return $response;
    });

    $app->get('/users', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $stmt = $pdo->query("SELECT * FROM users ORDER BY created_at DESC");
        $users = $stmt->fetchAll();

        $view = Twig::fromRequest($request);
        return $view->render($response, 'users.twig', ['users' => $users]);
    });

    $app->post('/users/add', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $data = $request->getParsedBody();
        
        $stmt = $pdo->prepare("INSERT INTO users (name, email) VALUES (:name, :email)");
        $stmt->execute([
            ':name' => $data['name'],
            ':email' => $data['email']
        ]);

        return $response
            ->withHeader('Location', '/users')
            ->withStatus(302);
    });

    $app->get('/stages', [StageController::class, 'list']);

    $app->get('/login', [AuthController::class, 'loginForm'])->setName('login');
    $app->get('/register', [AuthController::class, 'registerForm'])->setName('register');
    $app->post('/register', [\App\Controller\AuthController::class, 'register']);

    $app->get('/forgot-password', [AuthController::class, 'forgotPasswordForm'])->setName('forgot-password');

    $app->post('/login', [AuthController::class, 'login']);

    $app->get('/logout', function ($request, $response) {
        session_destroy();
        return $response->withHeader('Location', '/login')->withStatus(302);
    });
};



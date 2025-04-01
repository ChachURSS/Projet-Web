<?php

use Psr\Container\ContainerInterface;
use Slim\Views\Twig;
use App\Controller\AuthController;

return function (\DI\ContainerBuilder $containerBuilder) {
    $containerBuilder->addDefinitions([
        AuthController::class => function ($c) {
            return new AuthController($c->get(\Slim\Views\Twig::class));
        },

        PDO::class => function (ContainerInterface $c) {
            $host = $_ENV['DB_HOST'];
            $db   = $_ENV['DB_NAME'];
            $user = $_ENV['DB_USER'];
            $pass = $_ENV['DB_PASS'];

            $dsn = "mysql:host=$host;dbname=$db;port=3306;charset=utf8mb4";
            $options = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ];

            return new PDO($dsn, $user, $pass, $options);
        },

        Twig::class => function () {
            return Twig::create(__DIR__ . '/../templates', ['cache' => false]);
        },
    ]);
};

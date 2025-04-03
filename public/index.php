<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

use DI\ContainerBuilder;
use Slim\Factory\AppFactory;
use Slim\Views\Twig;
use Slim\Views\TwigMiddleware;
use Dotenv\Dotenv;

use App\Middleware\AuthMiddleware;

require __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

$containerBuilder = new ContainerBuilder();
$settings = require __DIR__ . '/../app/settings.php';
$settings($containerBuilder);
$dependencies = require __DIR__ . '/../app/dependencies.php';
$dependencies($containerBuilder);
$container = $containerBuilder->build();

AppFactory::setContainer($container);
$app = AppFactory::create();

$twig = Twig::create(__DIR__ . '/../templates', ['cache' => false]);
$twig->addExtension(new \Twig\Extension\DebugExtension());
$twig->getEnvironment()->addGlobal('session', $_SESSION);

$twig = Twig::create(__DIR__ . '/../templates', ['cache' => false]);
$app->add(TwigMiddleware::create($app, $twig));

$app->addRoutingMiddleware();
$app->addErrorMiddleware(true, true, true);

$routes = require __DIR__ . '/../app/routes.php';
$routes($app);

$app->add(new AuthMiddleware());

$app->run();

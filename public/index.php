<?php
session_start();

use DI\ContainerBuilder;
use Slim\Factory\AppFactory;
use Slim\Views\Twig;
use Slim\Views\TwigMiddleware;
use Dotenv\Dotenv;
use Slim\Exception\HttpNotFoundException;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
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

$routes = require __DIR__ . '/../app/middleware.php';
$routes = require __DIR__ . '/../app/routes.php';
$routes($app);

//$app->add(TwigMiddleware::createFromContainer($app, Twig::class));

$errorMiddleware = $app->addErrorMiddleware(true, true, true);
$errorMiddleware->setErrorHandler(
    HttpNotFoundException::class,
    function (
        Request $request,
        \Throwable $exception,
        bool $displayErrorDetails
    ) use ($app): Response {
        $container = $app->getContainer();
        $view = $container->get(Twig::class);
        $response = new \Slim\Psr7\Response();
        return $view->render($response->withStatus(404), '404.twig');
    }
);

$app->add(new AuthMiddleware());
$app->run();
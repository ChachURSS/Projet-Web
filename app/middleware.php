<?php

declare(strict_types=1);

use App\Application\Middleware\SessionMiddleware;
use Slim\App;
use Slim\Views\Twig;

return function (App $app) {
    $app->add(function ($request, $handler) {
        $view = Twig::fromRequest($request);
        $pdo = $this->get(PDO::class);

        $role = null;
        if (isset($_SESSION['token'])) {
            $role = getUserRole($pdo, $_SESSION['token']);
        }

        $view->getEnvironment()->addGlobal('role', $role);

        error_log("DEBUG: Rôle injecté dans Twig : " . ($role ?? 'null'));

        return $handler->handle($request);
    });

    $app->add(SessionMiddleware::class);
};

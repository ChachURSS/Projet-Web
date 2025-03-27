<?php

namespace App\Middleware;

use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as Handler;
use Psr\Http\Message\ResponseInterface;
use Slim\Routing\RouteContext;

class AuthMiddleware
{
    public function __invoke(Request $request, Handler $handler): ResponseInterface {


        $session = $_SESSION ?? [];

        $uri = $request->getUri()->getPath();

        $excludedPaths = ['/login', '/register', '/forgot-password'];

        if (!isset($session['user']) && !in_array($uri, $excludedPaths)) {
            $response = new \Slim\Psr7\Response();
            return $response
                ->withHeader('Location', '/login')
                ->withStatus(302);
        }

        return $handler->handle($request);
    }

}

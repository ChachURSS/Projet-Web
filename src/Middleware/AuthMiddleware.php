<?php

namespace App\Middleware;

use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as Handler;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Response;

class AuthMiddleware
{
    public function __invoke(Request $request, Handler $handler): ResponseInterface
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $uri = $request->getUri()->getPath();
        $method = $request->getMethod();

        $excludedRoutes = [
            ['GET', '/login'],
            ['POST', '/login'],
            ['GET', '/register'],
            ['POST', '/register'],
            ['GET', '/forgot-password'],
            ['POST', '/forgot-password']
        ];

        foreach ($excludedRoutes as [$excludedMethod, $excludedPath]) {
            if ($method === $excludedMethod && $uri === $excludedPath) {
                return $handler->handle($request);
            }
        }

        if (!isset($_SESSION['token'])) {
            return (new Response())->withHeader('Location', '/login')->withStatus(302);
        }

        return $handler->handle($request);
    }
}

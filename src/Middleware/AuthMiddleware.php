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
        $uri = $request->getUri()->getPath();
        $excludedPaths = ['/login', '/register', '/forgot-password'];

        if (!isset($_SESSION['token']) && !in_array($uri, $excludedPaths)) {
            return (new Response())->withHeader('Location', '/login')->withStatus(302);
        }

        return $handler->handle($request);
    }
}

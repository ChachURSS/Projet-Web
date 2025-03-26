<?php

namespace App\Controller;

use PDO;
use Slim\Views\Twig;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

class StageController
{
    private PDO $pdo;
    private Twig $twig;

    public function __construct(PDO $pdo, Twig $twig)
    {
        $this->pdo = $pdo;
        $this->twig = $twig;
    }

    public function list(Request $request, Response $response): Response
    {
        $stmt = $this->pdo->query("SELECT * FROM stages");
        $stages = $stmt->fetchAll();

        return $this->twig->render($response, 'stages.twig', [
            'stages' => $stages
        ]);
    }
}

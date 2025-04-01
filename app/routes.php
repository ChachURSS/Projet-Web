<?php

use Slim\App;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\Twig;
use App\Controller\StageController;
use App\Controller\AuthController;
use App\Middleware\AuthMiddleware;

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

    $app->get('/home', function (Request $request, Response $response, $args) {
        $view = Twig::fromRequest($request);
        return $view->render($response, 'home.twig');
    })->add(new AuthMiddleware());

    $app->get('/organization', function ($request, $response, $args) {
        $pdo = $this->get(PDO::class);
        $view = Twig::fromRequest($request);
    
        if (!isset($_SESSION['token'])) {
            return $response->withHeader('Location', '/login')->withStatus(302);
        }
    
        $stmt = $pdo->prepare("SELECT * FROM users WHERE token = :token");
        $stmt->execute(['token' => $_SESSION['token']]);
        $user = $stmt->fetch();
    
        if (!$user) {
            return $response->withHeader('Location', '/login')->withStatus(302);
        }
    
        $stmtOrg = $pdo->prepare("SELECT * FROM organizations WHERE id_organization = :id");
        $stmtOrg->execute(['id' => $user['id_organization']]);
        $organization = $stmtOrg->fetch();
    
        return $view->render($response, 'organization.twig', [
            'organization' => $organization,
            'role' => $user['role']
        ]);
    });

    $app->get('/companies', function ($request, $response, $args) {
    $pdo = $this->get(PDO::class);
    $view = Twig::fromRequest($request);

    if (!isset($_SESSION['token'])) {
        return $response->withHeader('Location', '/login')->withStatus(302);
    }

    $stmt = $pdo->prepare("SELECT * FROM users WHERE token = :token");
    $stmt->execute(['token' => $_SESSION['token']]);
    $user = $stmt->fetch();

    if (!$user) {
        return $response->withHeader('Location', '/login')->withStatus(302);
    }

    return $view->render($response, 'entreprise.twig', [
        'role' => $user['role']
    ]);
});

    
    // Route GET : page d'édition d'organisation (admins uniquement)
    $app->get('/organization/edit', function ($request, $response, $args) {
        $pdo = $this->get(PDO::class);
        $view = Twig::fromRequest($request);

        $stmt = $pdo->prepare("SELECT * FROM users WHERE token = :token");
        $stmt->execute(['token' => $_SESSION['token']]);
        $user = $stmt->fetch();

        if (!$user || $user['role'] != 0) {
            return $response->withHeader('Location', '/organization')->withStatus(302);
        }

        $stmtOrg = $pdo->prepare("SELECT * FROM organizations WHERE id_organization = :id");
        $stmtOrg->execute(['id' => $user['id_organization']]);
        $organization = $stmtOrg->fetch();

        return $view->render($response, 'organization_edit.twig', [
            'organization' => $organization
        ]);
    });

    // Route GET : gestion des membres (admin + pilote)
    $app->get('/organization/members', function ($request, $response, $args) {
        $pdo = $this->get(PDO::class);
        $view = Twig::fromRequest($request);

        $stmt = $pdo->prepare("SELECT * FROM users WHERE token = :token");
        $stmt->execute(['token' => $_SESSION['token']]);
        $user = $stmt->fetch();

        if (!$user || $user['role'] > 1) {
            return $response->withHeader('Location', '/organization')->withStatus(302);
        }

        $stmtMembers = $pdo->prepare("SELECT * FROM users WHERE id_organization = :org_id ORDER BY role");
        $stmtMembers->execute(['org_id' => $user['id_organization']]);
        $members = $stmtMembers->fetchAll();

        return $view->render($response, 'organization_members.twig', [
            'members' => $members,
            'role' => $user['role']
        ]);
    });

    $app->post('/organization/update', function ($request, $response, $args) {
        $pdo = $this->get(PDO::class);
    
        $stmt = $pdo->prepare("SELECT * FROM users WHERE token = :token");
        $stmt->execute(['token' => $_SESSION['token']]);
        $user = $stmt->fetch();
    
        if (!$user || $user['role'] != 0) {
            return $response->withHeader('Location', '/organization')->withStatus(403);
        }
    
        $data = $request->getParsedBody();
        $name = trim($data['name'] ?? '');
        $description = trim($data['description'] ?? '');
        $delete_logo = isset($data['delete_logo']);
    
        $stmtOrg = $pdo->prepare("SELECT path_to_icon FROM organizations WHERE id_organization = :id");
        $stmtOrg->execute(['id' => $user['id_organization']]);
        $org = $stmtOrg->fetch();
        $old_logo = $org['path_to_icon'];
    
        $upload_dir = __DIR__ . '/../public/uploads/';
        $public_path_prefix = '/uploads/';
        $new_logo_path = null;
    
        if (!empty($_FILES['logo']['tmp_name'])) {
            $file = $_FILES['logo'];
            $mime = mime_content_type($file['tmp_name']);
    
            if (str_starts_with($mime, 'image/')) {
                $base_name = pathinfo($file['name'], PATHINFO_FILENAME);
                $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
                $safe_name = preg_replace('/[^a-zA-Z0-9_-]/', '_', $base_name);
                $filename = $safe_name . '.' . $extension;
                $i = 1;
    
                while (file_exists($upload_dir . $filename)) {
                    $filename = $safe_name . '_' . $i . '.' . $extension;
                    $i++;
                }
    
                $target_path = $upload_dir . $filename;
                if (move_uploaded_file($file['tmp_name'], $target_path)) {
                    $new_logo_path = $public_path_prefix . $filename;
    
                    if ($old_logo && file_exists(__DIR__ . '/../public' . $old_logo)) {
                        unlink(__DIR__ . '/../public' . $old_logo);
                    }
                }
            }
        }
    
        if ($delete_logo && $old_logo && file_exists(__DIR__ . '/../public' . $old_logo)) {
            unlink(__DIR__ . '/../public' . $old_logo);
            $new_logo_path = null;
        }
    
        $query = "UPDATE organizations SET name = :name, description = :description";
        $params = ['name' => $name, 'description' => $description, 'id' => $user['id_organization']];
    
        if (!is_null($new_logo_path)) {
            $query .= ", path_to_icon = :icon";
            $params['icon'] = $new_logo_path;
        } elseif ($delete_logo) {
            $query .= ", path_to_icon = NULL";
        }
    
        $query .= " WHERE id_organization = :id";
        $stmt = $pdo->prepare($query);
        $stmt->execute($params);
    
        return $response->withHeader('Location', '/organization')->withStatus(302);
    });

    $app->post('/organization/delete-user', function ($request, $response, $args) {
        $pdo = $this->get(PDO::class);
        $data = $request->getParsedBody();
        $id_user = (int)($data['id_user'] ?? 0);
    
        $stmt = $pdo->prepare("SELECT * FROM users WHERE token = :token");
        $stmt->execute(['token' => $_SESSION['token']]);
        $admin = $stmt->fetch();
    
        if (!$admin || $admin['role'] != 0) {
            return $response->withHeader('Location', '/organization')->withStatus(403);
        }
    
        // Vérifie que le membre appartient à la même organisation
        $stmtCheck = $pdo->prepare("SELECT * FROM users WHERE id_user = :id_user AND id_organization = :org");
        $stmtCheck->execute([
            'id_user' => $id_user,
            'org' => $admin['id_organization']
        ]);
        $target = $stmtCheck->fetch();
    
        if ($target && $target['role'] != 0) {
            $stmtDel = $pdo->prepare("DELETE FROM users WHERE id_user = :id_user");
            $stmtDel->execute(['id_user' => $id_user]);
        }
    
        return $response->withHeader('Location', '/organization/members')->withStatus(302);
    });
    
    $app->get('/organization/logo/{filename}', function ($request, $response, $args) {
        $filename = basename($args['filename']);
        $filepath = __DIR__ . '/../private/uploads/' . $filename;
    
        if (!isset($_SESSION['token']) || !file_exists($filepath)) {
            return $response->withStatus(403);
        }
    
        $stream = new \Slim\Psr7\Stream(fopen($filepath, 'rb'));
        return $response
            ->withBody($stream)
            ->withHeader('Content-Type', mime_content_type($filepath))
            ->withHeader('Content-Disposition', 'inline; filename="' . $filename . '"');
    });


// Afficher le formulaire d'ajout d'une entreprise
    $app->get('/company/create', function ($request, $response, $args) {
        return $this->get('view')->render($response, 'entreprise_add.twig');
    })->setName('company.create');

    // Traiter l'ajout d'une entreprise
    $app->post('/company/add', function ($request, $response, $args) {
        $data = $request->getParsedBody();
        $name = $data['name'];
        $description = $data['description'];
        $icon_path = $data['icon_path'];
        $icon_link = $data['icon_link'];

        $sql = "INSERT INTO companies (name, description, icon_path, icon_link) VALUES (:name, :description, :icon_path, :icon_link)";
        $stmt = $this->get('db')->prepare($sql);
        $stmt->execute([
            ':name' => $name,
            ':description' => $description,
            ':icon_path' => $icon_path,
            ':icon_link' => $icon_link
        ]);

        return $response->withHeader('Location', '/')->withStatus(302);
    })->setName('company.add');




};



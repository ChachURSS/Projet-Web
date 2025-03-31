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
    
        $stmt = $pdo->prepare("SELECT * FROM users WHERE token = :token");
        $stmt->execute(['token' => $_SESSION['token']]);
        $user = $stmt->fetch();
    
        if (!$user) {
            return $response->withHeader('Location', '/login')->withStatus(302);
        }
    
        $stmtOrg = $pdo->prepare("SELECT * FROM organizations WHERE id_organization = :id");
        $stmtOrg->execute(['id' => $user['id_organization']]);
        $organization = $stmtOrg->fetch();
    
        if (!$organization) {
            return $response->withHeader('Location', '/login')->withStatus(302);
        }
    
        if ($user['role'] == 0) {
            // admin → tous les membres
            $stmtMembers = $pdo->prepare("SELECT * FROM users WHERE id_organization = :org");
            $stmtMembers->execute(['org' => $user['id_organization']]);
        } elseif ($user['role'] == 1) {
            // pilote → les élèves et lui-même
            $stmtMembers = $pdo->prepare("SELECT * FROM users WHERE id_organization = :org AND (role = 2 OR id_user = :self)");
            $stmtMembers->execute([
                'org' => $user['id_organization'],
                'self' => $user['id_user']
            ]);
        } else {
            // élève → lui-même uniquement
            $stmtMembers = $pdo->prepare("SELECT * FROM users WHERE id_user = :self AND id_organization = :org");
            $stmtMembers->execute([
                'self' => $user['id_user'],
                'org' => $user['id_organization']
            ]);
        }
    
        $members = $stmtMembers->fetchAll();
    
        return $view->render($response, 'organization.twig', [
            'organization' => $organization,
            'role' => $user['role'],
            'members' => $members,
            'current_user_id' => $user['id_user']
        ]);
    });
    
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
    
    // Route GET : page d'édition d'organisation (admins uniquement)
    $app->get('/organization/member/{id}/edit', function ($request, $response, $args) {
        $pdo = $this->get(PDO::class);
        $view = Twig::fromRequest($request);
        $id = (int)$args['id'];
    
        $stmt = $pdo->prepare("SELECT * FROM users WHERE token = :token");
        $stmt->execute(['token' => $_SESSION['token']]);
        $current = $stmt->fetch();
    
        $stmtUser = $pdo->prepare("SELECT * FROM users WHERE id_user = :id_user AND id_organization = :org");
        $stmtUser->execute(['id_user' => $id, 'org' => $current['id_organization']]);
        $member = $stmtUser->fetch();
    
        if (!$member) {
            return $response->withHeader('Location', '/organization')->withStatus(302);
        }
    
        $isSelf = $current['id_user'] === $member['id_user'];
        $canEdit = ($current['role'] == 0) || ($current['role'] == 1 && ($member['role'] == 2 || $isSelf)) || $isSelf;
        $canDelete = (
            ($current['role'] == 0 && !$isSelf) ||
            ($current['role'] == 1 && $member['role'] == 2 && !$isSelf)
        );
    
        if (!$canEdit) {
            return $response->withHeader('Location', '/organization')->withStatus(403);
        }
    
        $response = $view->render($response, 'organization_members.twig', [
            'member' => $member,
            'canDelete' => $canDelete,
            'isAdmin' => $current['role'] == 0,
            'current_user_id' => $current['id_user'],
            'session' => $_SESSION
        ]);
    
        unset($_SESSION['flash_error']);
        return $response;
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

    $app->post('/organization/member/delete', function ($request, $response, $args) {
        $pdo = $this->get(PDO::class);
        $data = $request->getParsedBody();
        $id_user = (int)$data['id_user'];
    
        $stmt = $pdo->prepare("SELECT * FROM users WHERE token = :token");
        $stmt->execute(['token' => $_SESSION['token']]);
        $current = $stmt->fetch();
    
        if (!$current || $current['role'] != 0 || $current['id_user'] == $id_user) {
            return $response->withHeader('Location', '/organization')->withStatus(403);
        }
    
        $stmtCheck = $pdo->prepare("SELECT * FROM users WHERE id_user = :id_user AND id_organization = :org");
        $stmtCheck->execute(['id_user' => $id_user, 'org' => $current['id_organization']]);
        $target = $stmtCheck->fetch();
    
        if (!$target) {
            return $response->withHeader('Location', '/organization')->withStatus(302);
        }
    
        $stmtDel = $pdo->prepare("DELETE FROM users WHERE id_user = :id_user");
        $stmtDel->execute(['id_user' => $id_user]);
    
        return $response->withHeader('Location', '/organization')->withStatus(302);
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
    
    $app->post('/organization/member/update', function ($request, $response, $args) {
        $pdo = $this->get(PDO::class);
        $data = $request->getParsedBody();
    
        $stmt = $pdo->prepare("SELECT * FROM users WHERE token = :token");
        $stmt->execute(['token' => $_SESSION['token']]);
        $current = $stmt->fetch();
    
        $id_user = (int)$data['id_user'];
        if (!$current) {
            return $response->withHeader('Location', '/organization')->withStatus(403);
        }
    
        $stmtCheck = $pdo->prepare("SELECT * FROM users WHERE id_user = :id_user AND id_organization = :org");
        $stmtCheck->execute(['id_user' => $id_user, 'org' => $current['id_organization']]);
        $target = $stmtCheck->fetch();
    
        $isSelf = $current['id_user'] === $id_user;
    
        if (!$target || ($current['role'] == 1 && !$isSelf && $target['role'] != 2)) {
            return $response->withHeader('Location', '/organization')->withStatus(403);
        }
    
        $input_mail = trim($data['mail']);
        try {
            $stmtMail = $pdo->prepare("SELECT id_user FROM users WHERE mail = :mail AND id_user != :id_user");
            $stmtMail->execute([
                'mail' => $input_mail,
                'id_user' => $id_user
            ]);
    
            if ($stmtMail->fetch()) {
                $_SESSION['flash_error'] = "L'adresse email est déjà utilisée.";
                return $response->withHeader('Location', '/organization/member/' . $id_user . '/edit')->withStatus(302);
            }
    
            $params = [
                'id_user' => $id_user,
                'name' => trim($data['name']),
                'last_name' => trim($data['last_name']),
                'mail' => $input_mail
            ];
    
            $query = "UPDATE users SET name = :name, last_name = :last_name, mail = :mail";
    
            $mailChanged = $input_mail !== $target['mail'];
            $passwordChanged = !empty($data['password']);
    
            if ($passwordChanged) {
                $query .= ", password = :password";
                $params['password'] = password_hash($data['password'], PASSWORD_DEFAULT);
            }
    
            if ($mailChanged || $passwordChanged) {
                $query .= ", token = :token";
                $params['token'] = bin2hex(random_bytes(25));
            }
    
            if ($current['role'] == 0 && isset($data['role']) && !$isSelf) {
                $query .= ", role = :role";
                $params['role'] = (int)$data['role'];
            }
    
            $query .= " WHERE id_user = :id_user";
            $stmt = $pdo->prepare($query);
            $stmt->execute($params);
    
            return $response->withHeader('Location', '/organization')->withStatus(302);
        } catch (PDOException $e) {
            $_SESSION['flash_error'] = "Erreur lors de la mise à jour du compte.";
            return $response->withHeader('Location', '/organization/member/' . $id_user . '/edit')->withStatus(302);
        }
    });

    $app->post('/organization/add-user', function ($request, $response, $args) {
        $pdo = $this->get(PDO::class);
        $data = $request->getParsedBody();

        $stmt = $pdo->prepare("SELECT * FROM users WHERE token = :token");
        $stmt->execute(['token' => $_SESSION['token']]);
        $user = $stmt->fetch();

        if (!$user || ($user['role'] == 1 && $data['role'] != 2)) {
            return $response->withHeader('Location', '/organization')->withStatus(403);
        }

        $stmt = $pdo->prepare("INSERT INTO users (token, mail, password, name, last_name, role, id_organization)
                                VALUES (:token, :mail, :password, :name, :last_name, :role, :id_organization)");

        $stmt->execute([
            'token' => bin2hex(random_bytes(25)),
            'mail' => trim($data['mail']),
            'password' => password_hash($data['password'], PASSWORD_DEFAULT),
            'name' => trim($data['prenom']),
            'last_name' => trim($data['nom']),
            'role' => (int)$data['role'],
            'id_organization' => $user['id_organization']
        ]);

        return $response->withHeader('Location', '/organization')->withStatus(302);
    });

};



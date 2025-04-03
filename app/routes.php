<?php

use Slim\App;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\Twig;
use App\Controller\StageController;
use App\Controller\AuthController;
use App\Middleware\AuthMiddleware;

// Vérification et démarrage de la session
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
error_log("DEBUG: Contenu de la session : " . json_encode($_SESSION));

/**
 * Fonction pour récupérer le rôle de l'utilisateur depuis la base de données.
 */
function getUserRole(PDO $pdo, string $token): ?int {
    $stmt = $pdo->prepare("SELECT role FROM users WHERE token = :token");
    $stmt->execute([':token' => $token]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        return (int)$user['role'];
    }

    return null; // Retourne null si aucun utilisateur n'est trouvé
}

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

    //$app->get('/forgot-password', [AuthController::class, 'forgotPasswordForm'])->setName('forgot-password');

    $app->post('/login', function (Request $request, Response $response) {
        $pdo = $this->get(PDO::class);
        $data = $request->getParsedBody();

        error_log("DEBUG: Données reçues pour la connexion : " . json_encode($data));

        if (empty($data['email']) || empty($data['mdp'])) {
            $_SESSION['flash_error'] = "Veuillez remplir tous les champs.";
            return $response->withHeader('Location', '/login')->withStatus(302);
        }

        $stmt = $pdo->prepare("SELECT * FROM users WHERE mail = :mail");
        $stmt->execute([':mail' => $data['email']]);
        $user = $stmt->fetch();

        if ($user && password_verify($data['mdp'], $user['password'])) {
            $_SESSION['user_id'] = $user['id_user'];
            $_SESSION['token'] = $user['token'];
            $_SESSION['role'] = $user['role']; // Assurez-vous que cette ligne est présente

            // Journaliser le rôle pour déboguer
            error_log("DEBUG: Rôle utilisateur après connexion : " . $_SESSION['role']);

            return $response->withHeader('Location', '/home')->withStatus(302);
        } else {
            $_SESSION['flash_error'] = "Identifiants incorrects.";
            return $response->withHeader('Location', '/login')->withStatus(302);
        }
    });

    $app->get('/forgot-password', function ($request, $response) {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    
        $view = $this->get(Slim\Views\Twig::class);
    
        $flash_error = $_SESSION['flash_error'] ?? null;
        $flash_success = $_SESSION['flash_success'] ?? null;
    
        unset($_SESSION['flash_error'], $_SESSION['flash_success']);
    
        return $view->render($response, 'forgot_password.twig', [
            'flash_error' => $flash_error,
            'flash_success' => $flash_success
        ]);
    });

    $app->post('/forgot-password', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $twig = $this->get(Twig::class);
    
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    
        $data = $request->getParsedBody();
        $email = trim($data['email'] ?? '');
        $message = null;
        $messageType = null;
    
        if (!empty($email)) {
            $stmt = $pdo->prepare("SELECT * FROM users WHERE mail = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
            if ($user) {
                $tempPassword = bin2hex(random_bytes(4));
                $hashedPassword = password_hash($tempPassword, PASSWORD_DEFAULT);
    
                $stmt = $pdo->prepare("UPDATE users SET password = :password WHERE id_user = :id_user");
                $stmt->execute([
                    'password' => $hashedPassword,
                    'id_user' => $user['id_user']
                ]);
    
                $to = $email;
                $subject = "Réinitialisation de mot de passe EasyStage";
                $body = "Bonjour,\n\nVoici votre mot de passe temporaire : $tempPassword\n\nConnectez-vous et changez-le dès que possible.\n\nCordialement,\nL'équipe EasyStage";
                $headers = "From: noreply@easystage.local";
    
                
                $logPath = __DIR__ . '/../logs/mail.log';
                $logContent = "To: $to\nSubject: $subject\nHeaders: $headers\n\n$body\n\n------------------------\n";
    
                if (file_put_contents($logPath, $logContent, FILE_APPEND)) {
                    $_SESSION['flash_success'] = "Un mot de passe temporaire a été généré et simulé (voir fichier log).";
                } else {
                    $_SESSION['flash_error'] = "Erreur lors de la simulation de l'envoi. Veuillez contacter un administrateur.";
                }
    
                return $response
                    ->withHeader('Location', '/forgot-password')
                    ->withStatus(302);
            } else {
                $message = "Aucun compte associé à cette adresse email.";
                $messageType = "error";
            }
        } else {
            $message = "Veuillez entrer une adresse email.";
            $messageType = "error";
        }
    
        return $twig->render($response, 'forgot_password.twig', [
            'flash_error' => $messageType === 'error' ? $message : null,
            'flash_success' => $messageType === 'success' ? $message : null
        ]);
    });
    
    

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
        $view = $this->get(Slim\Views\Twig::class);
    
        $stmt = $pdo->prepare("SELECT * FROM users WHERE token = :token");
        $stmt->execute(['token' => $_SESSION['token']]);
        $currentUser = $stmt->fetch();
    
        if (!$currentUser) {
            return $response->withHeader('Location', '/login')->withStatus(302);
        }
    
        $role = $currentUser['role'];
        $id_organization = $currentUser['id_organization'];
        $current_user_id = $currentUser['id_user'];
    
        if ($role == 0) {
            
            $stmt = $pdo->prepare("SELECT * FROM users WHERE id_organization = :org");
            $stmt->execute(['org' => $id_organization]);
        } elseif ($role == 1) {
            
            $stmt = $pdo->prepare("SELECT * FROM users WHERE id_organization = :org AND (role = 2 OR id_user = :me)");
            $stmt->execute(['org' => $id_organization, 'me' => $current_user_id]);
        } elseif ($role == 2) {
            
            $stmt = $pdo->prepare("SELECT * FROM users WHERE id_user = :me");
            $stmt->execute(['me' => $current_user_id]);
        } else {
            return $response->withHeader('Location', '/login')->withStatus(302);
        }
    
        $members = $stmt->fetchAll();

        $stmt = $pdo->prepare("SELECT * FROM organizations WHERE id_organization = :id");
        $stmt->execute(['id' => $id_organization]);
        $organization = $stmt->fetch();
    
        return $view->render($response, 'organization.twig', [
            'organization' => $organization,
            'members' => $members,
            'role' => $role,
            'current_user_id' => $current_user_id,
            'session' => $_SESSION
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
    
        // Vérifie si l'email est déjà utilisé
        $check = $pdo->prepare("SELECT id_user FROM users WHERE mail = :mail");
        $check->execute(['mail' => trim($data['mail'])]);
        if ($check->fetch()) {
            $_SESSION['flash_error'] = "Cette adresse email est déjà utilisée.";
            return $response->withHeader('Location', '/organization')->withStatus(302);
        }
    
        try {
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
    
        } catch (PDOException $e) {
            $_SESSION['flash_error'] = "Une erreur est survenue lors de l'ajout du membre.";
            return $response->withHeader('Location', '/organization')->withStatus(302);
        }
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

        // Récupérer les entreprises
        $stmtCompanies = $pdo->query("SELECT * FROM companies");
        $companies = $stmtCompanies->fetchAll();

        return $view->render($response, 'entreprise.twig', [
            'companies' => $companies,
            'role' => $user['role']
        ]);
    });
        //Suppression d'une entreprise
        $app->post('/companies/delete/{id}', function (Request $request, Response $response, $args) {
            $pdo = $this->get(PDO::class);
            $id_company = (int)$args['id'];

            $stmt = $pdo->prepare("DELETE FROM companies WHERE id_company = :id");
            $stmt->execute([':id' => $id_company]);

            return $response->withHeader('Location', '/companies')->withStatus(302);
        });

        $app->post('/company/add', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);

        $stmt = $pdo->prepare("SELECT * FROM users WHERE token = :token");
        $stmt->execute(['token' => $_SESSION['token']]);
        $user = $stmt->fetch();

        if (!$user) {
            return $response->withHeader('Location', '/login')->withStatus(302);
        }

        $data = $request->getParsedBody();
        $name = trim($data['name'] ?? '');
        $description = trim($data['description'] ?? '');

        $upload_dir = __DIR__ . '/../public/uploads/';
        $public_path_prefix = '/uploads/';
        $new_logo_path = null;

        if (!empty($_FILES['path_to_icon']['tmp_name'])) {
            $file = $_FILES['path_to_icon'];
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
                }
            }
        }

        $sql = "INSERT INTO companies (name, description, path_to_icon) VALUES (:name, :description, :path_to_icon)";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':name' => $name,
            ':description' => $description,
            ':path_to_icon' => $new_logo_path
        ]);

        return $response->withHeader('Location', '/companies')->withStatus(302);
    })->setName('company.add');

// GET : Afficher le formulaire de modification d'une entreprise
    $app->get('/companies/edit/{id}', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $view = Twig::fromRequest($request);
        $id_company = (int)$args['id'];

        $stmt = $pdo->prepare("SELECT * FROM companies WHERE id_company = :id");
        $stmt->execute([':id' => $id_company]);
        $company = $stmt->fetch();

        return $view->render($response, 'entreprise_edit.twig', ['company' => $company]);
    });

    // Route POST : Mettre à jour une entreprise
    $app->post('/company/update', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);

        $stmt = $pdo->prepare("SELECT * FROM users WHERE token = :token");
        $stmt->execute(['token' => $_SESSION['token']]);
        $user = $stmt->fetch();

        if (!$user) {
            return $response->withHeader('Location', '/login')->withStatus(302);
        }

        $data = $request->getParsedBody();
        $id_company = (int)$data['id_company'];
        $name = trim($data['name'] ?? '');
        $description = trim($data['description'] ?? '');
        $delete_logo = isset($data['delete_logo']);

        $stmtOrg = $pdo->prepare("SELECT path_to_icon FROM companies WHERE id_company = :id");
        $stmtOrg->execute(['id' => $id_company]);
        $comp = $stmtOrg->fetch();
        $old_logo = $comp['path_to_icon'];

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

        $query = "UPDATE companies SET name = :name, description = :description";
        $params = ['name' => $name, 'description' => $description, 'id' => $id_company];

        if (!is_null($new_logo_path)) {
            $query .= ", path_to_icon = :icon";
            $params['icon'] = $new_logo_path;
        } elseif ($delete_logo) {
            $query .= ", path_to_icon = NULL";
        }

        $query .= " WHERE id_company = :id";
        $stmt = $pdo->prepare($query);
        $stmt->execute($params);

        return $response->withHeader('Location', '/companies')->withStatus(302);
    });

    // POST : Modifier une entreprise
    $app->post('/companies/edit/{id}', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $data = $request->getParsedBody();
        $id_company = (int)$args['id'];

        $name = trim($data['name'] ?? '');
        $description = trim($data['description'] ?? '');
        $delete_logo = isset($data['delete_logo']);

        $stmtOrg = $pdo->prepare("SELECT path_to_icon FROM companies WHERE id_company = :id");
        $stmtOrg->execute(['id' => $id_company]);
        $comp = $stmtOrg->fetch();
        $old_logo = $comp['path_to_icon'];

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

        $query = "UPDATE companies SET name = :name, description = :description";
        $params = ['name' => $name, 'description' => $description, 'id' => $id_company];

        if (!is_null($new_logo_path)) {
            $query .= ", path_to_icon = :icon";
            $params['icon'] = $new_logo_path;
        } elseif ($delete_logo) {
            $query .= ", path_to_icon = NULL";
        }

        $query .= " WHERE id_company = :id";
        $stmt = $pdo->prepare($query);
        $stmt->execute($params);

        return $response->withHeader('Location', '/companies')->withStatus(302);
    });
    

// Afficher le formulaire d'ajout d'une entreprise
    $app->get('/company/create', function ($request, $response, $args) {
        return $this->get('view')->render($response, 'entreprise_add.twig');
    })->setName('company.create');

    // Traiter l'ajout d'une entreprise
    
    // GET : Afficher les détails d'une entreprise
    $app->get('/companies/detail/{id}', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $view = Twig::fromRequest($request);
        $id_company = (int)$args['id'];

        $stmt = $pdo->prepare("SELECT * FROM companies WHERE id_company = :id");
        $stmt->execute([':id' => $id_company]);
        $company = $stmt->fetch();

        $stmtInternships = $pdo->prepare("SELECT * FROM internships WHERE id_company = :id ORDER BY bdate DESC");
        $stmtInternships->execute([':id' => $id_company]);
        $internships = $stmtInternships->fetchAll();

        return $view->render($response, 'entreprise_detail.twig', [
            'company' => $company,
            'internships' => $internships
        ]);
    });


    // Route GET : Afficher les stages
    $app->get('/internships', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $view = Twig::fromRequest($request);

        $user_id = $_SESSION['user_id'] ?? null;
        $queryParams = $request->getQueryParams();
        $search = trim($queryParams['search'] ?? '');

        // Récupérer le rôle de l'utilisateur
        $role = null;
        if (isset($_SESSION['token'])) {
            $role = getUserRole($pdo, $_SESSION['token']);
        }

        $sql = "
            SELECT internships.*, companies.name AS company_name 
            FROM internships 
            JOIN companies ON internships.id_company = companies.id_company 
            WHERE (internships.title LIKE :search1 OR internships.description LIKE :search2 OR companies.name LIKE :search3)
        ";

        // Ajouter une condition pour exclure les offres indisponibles si le rôle est 2
        if ($role === 2) {
            $sql .= " AND internships.status = 1";
        }

        $sql .= " ORDER BY bdate DESC";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':search1' => '%' . $search . '%',
            ':search2' => '%' . $search . '%',
            ':search3' => '%' . $search . '%'
        ]);
        $internships = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($internships as &$internship) {
            $stmtTags = $pdo->prepare("
                SELECT int_tags.name 
                FROM have_itags 
                JOIN int_tags ON have_itags.id_itag = int_tags.id_itag 
                WHERE have_itags.id_internship = :id_internship
            ");
            $stmtTags->execute([':id_internship' => $internship['id_internship']]);
            $internship['tags'] = $stmtTags->fetchAll(PDO::FETCH_COLUMN);

            // Vérifier si l'utilisateur a ajouté ce stage à ses favoris
            if ($user_id) {
                $stmtFavorite = $pdo->prepare("
                    SELECT 1 
                    FROM favorite 
                    WHERE id_user = :id_user AND id_internship = :id_internship
                ");
                $stmtFavorite->execute([
                    ':id_user' => $user_id,
                    ':id_internship' => $internship['id_internship']
                ]);
                $internship['is_favorite'] = (bool) $stmtFavorite->fetchColumn();
            } else {
                $internship['is_favorite'] = false;
            }
        }

        return $view->render($response, 'internships.twig', [
            'internships' => $internships,
            'search' => $search,
            'role' => $role // Injecter le rôle dans Twig
        ]);
    });

$app->post('/rate-company', function (Request $request, Response $response) {
    $pdo = $this->get(PDO::class);
    $data = json_decode($request->getBody(), true);
    $userId = $_SESSION['user_id'] ?? null;

    if (!$userId) {
        return $response->withJson(['success' => false, 'message' => 'Vous devez être connecté.'], 401);
    }

    if (!isset($data['company_id'], $data['rating']) || !is_numeric($data['rating']) || $data['rating'] < 1 || $data['rating'] > 5) {
        return $response->withJson(['success' => false, 'message' => 'Données invalides.'], 400);
    }

    $companyId = (int) $data['company_id'];
    $rating = (int) $data['rating'];

    // Vérifier si l'utilisateur a déjà noté l'entreprise
    $stmt = $pdo->prepare("SELECT id_rating FROM rating WHERE id_user = :user_id AND id_company = :company_id");
    $stmt->execute(['user_id' => $userId, 'company_id' => $companyId]);
    $existingRating = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($existingRating) {
        // Mettre à jour la note existante
        $stmt = $pdo->prepare("UPDATE rating SET note = :rating WHERE id_user = :user_id AND id_company = :company_id");
    } else {
        // Insérer une nouvelle note
        $stmt = $pdo->prepare("INSERT INTO rating (id_user, id_company, note) VALUES (:user_id, :company_id, :rating)");
    }

    $stmt->execute(['user_id' => $userId, 'company_id' => $companyId, 'rating' => $rating]);

    return $response->withJson(['success' => true, 'message' => 'Note enregistrée avec succès !']);
});


    // Route GET : Afficher le formulaire d'ajout de stage
    $app->get('/internships/add', function (Request $request, Response $response, $args) {
        $view = Twig::fromRequest($request);
        return $view->render($response, 'add_internship.twig');
    });

    // Route POST : Ajouter un stage avec gestion de l'upload d'icône
    $app->post('/internships/add', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $data = $request->getParsedBody();

        $upload_dir = __DIR__ . '/../public/uploads/';
        $public_path_prefix = '/uploads/';
        $path_to_icon = null;

        // Gestion de l'upload d'icône
        if (!empty($_FILES['path_to_icon']['tmp_name'])) {
            $file = $_FILES['path_to_icon'];
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
                    $path_to_icon = $public_path_prefix . $filename;
                }
            }
        }

        // Vérification ou ajout de l'entreprise
        $company_name = trim($data['company_name']);
        $stmt = $pdo->prepare("SELECT id_company FROM companies WHERE name = :name");
        $stmt->execute([':name' => $company_name]);
        $company = $stmt->fetch();

        if ($company) {
            $id_company = $company['id_company'];
        } else {
            $stmt = $pdo->prepare("INSERT INTO companies (name) VALUES (:name)");
            $stmt->execute([':name' => $company_name]);
            $id_company = $pdo->lastInsertId();
        }

        // Gestion du statut (par défaut 0 si non activé)
        $status = isset($data['status']) ? $data['status'] : 0;

        // Ajout de l'annonce avec la date de post
        $stmt = $pdo->prepare("
            INSERT INTO internships (title, description, status, path_to_icon, bdate, edate, post_date, id_company)
            VALUES (:title, :description, :status, :path_to_icon, :bdate, :edate, :post_date, :id_company)
        ");
        $stmt->execute([
            ':title' => $data['title'],
            ':description' => $data['description'],
            ':status' => $status,
            ':path_to_icon' => $path_to_icon,
            ':bdate' => $data['bdate'],
            ':edate' => $data['edate'],
            ':post_date' => date('Y-m-d'),
            ':id_company' => $id_company
        ]);

        $id_internship = $pdo->lastInsertId();

        // Gestion des tags
        if (!empty($data['tags'])) {
            $tags = array_map('trim', explode(',', $data['tags']));
            foreach ($tags as $tag) {
                if (!empty($tag)) {
                    // Vérifier si le tag existe déjà
                    $stmt = $pdo->prepare("SELECT id_itag FROM int_tags WHERE name = :name");
                    $stmt->execute([':name' => $tag]);
                    $existingTag = $stmt->fetch();

                    if ($existingTag) {
                        $id_itag = $existingTag['id_itag'];
                    } else {
                        // Ajouter le tag s'il n'existe pas
                        $stmt = $pdo->prepare("INSERT INTO int_tags (name) VALUES (:name)");
                        $stmt->execute([':name' => $tag]);
                        $id_itag = $pdo->lastInsertId();
                    }

                    // Lier le tag à l'annonce
                    $stmt = $pdo->prepare("INSERT INTO have_itags (id_itag, id_internship) VALUES (:id_itag, :id_internship)");
                    $stmt->execute([
                        ':id_itag' => $id_itag,
                        ':id_internship' => $id_internship
                    ]);
                }
            }
        }

        return $response->withHeader('Location', '/internships')->withStatus(302);
    });

    // Route GET : Suggestions de tags pour l'autocomplétion
    $app->get('/tags/suggestions', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $queryParams = $request->getQueryParams();
        $query = trim($queryParams['query'] ?? '');

        if (!empty($query)) {
            $stmt = $pdo->prepare("SELECT name FROM int_tags WHERE name LIKE :query LIMIT 10");
            $stmt->execute([':query' => $query . '%']);
            $tags = $stmt->fetchAll(PDO::FETCH_ASSOC);
        } else {
            $tags = [];
        }

        $response->getBody()->write(json_encode($tags));
        return $response->withHeader('Content-Type', 'application/json');
    });

    // Route POST : Supprimer une offre
    $app->post('/internships/delete/{id}', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $id_internship = (int)$args['id'];

        $stmt = $pdo->prepare("DELETE FROM internships WHERE id_internship = :id");
        $stmt->execute([':id' => $id_internship]);

        return $response->withHeader('Location', '/internships')->withStatus(302);
    });

    // Route GET : Afficher le formulaire de modification d'une offre
    $app->get('/internships/edit/{id}', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $view = Twig::fromRequest($request);
        $id_internship = (int)$args['id'];

        $stmt = $pdo->prepare("
            SELECT internships.*, companies.name AS company_name 
            FROM internships 
            JOIN companies ON internships.id_company = companies.id_company 
            WHERE id_internship = :id
        ");
        $stmt->execute([':id' => $id_internship]);
        $internship = $stmt->fetch();

        if (!$internship) {
            return $response->withHeader('Location', '/internships')->withStatus(404);
        }

        // Récupérer les tags associés à l'offre
        $stmtTags = $pdo->prepare("
            SELECT int_tags.name 
            FROM have_itags 
            JOIN int_tags ON have_itags.id_itag = int_tags.id_itag 
            WHERE have_itags.id_internship = :id_internship
        ");
        $stmtTags->execute([':id_internship' => $id_internship]);
        $tags = $stmtTags->fetchAll(PDO::FETCH_COLUMN);

        // Ajouter les tags formatés à l'internship
        $internship['tags'] = $tags ? implode(', ', $tags) : '';

        return $view->render($response, 'edit_internship.twig', ['internship' => $internship]);
    });

    // Route POST : Modifier une offre
    $app->post('/internships/edit/{id}', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $data = $request->getParsedBody();
        $id_internship = (int)$args['id'];

        // Vérification ou ajout de l'entreprise
        $company_name = trim($data['company_name']);
        $stmt = $pdo->prepare("SELECT id_company FROM companies WHERE name = :name");
        $stmt->execute([':name' => $company_name]);
        $company = $stmt->fetch();

        if ($company) {
            $id_company = $company['id_company'];
        } else {
            $stmt = $pdo->prepare("INSERT INTO companies (name) VALUES (:name)");
            $stmt->execute([':name' => $company_name]);
            $id_company = $pdo->lastInsertId();
        }

        // Gestion du statut (par défaut 0 si non activé)
        $status = isset($data['status']) ? $data['status'] : 0;

        // Mise à jour de l'offre
        $stmt = $pdo->prepare("
            UPDATE internships 
            SET title = :title, description = :description, status = :status, bdate = :bdate, edate = :edate, id_company = :id_company 
            WHERE id_internship = :id
        ");
        $stmt->execute([
            ':title' => $data['title'],
            ':description' => $data['description'],
            ':status' => $status,
            ':bdate' => $data['bdate'],
            ':edate' => $data['edate'],
            ':id_company' => $id_company,
            ':id' => $id_internship
        ]);

        // Gestion des tags
        $stmt = $pdo->prepare("DELETE FROM have_itags WHERE id_internship = :id_internship");
        $stmt->execute([':id_internship' => $id_internship]);

        if (!empty($data['tags'])) {
            $tags = array_map('trim', explode(',', $data['tags']));
            foreach ($tags as $tag) {
                if (!empty($tag)) {
                    // Vérifier si le tag existe déjà
                    $stmt = $pdo->prepare("SELECT id_itag FROM int_tags WHERE name = :name");
                    $stmt->execute([':name' => $tag]);
                    $existingTag = $stmt->fetch();

                    if ($existingTag) {
                        $id_itag = $existingTag['id_itag'];
                    } else {
                        // Ajouter le tag s'il n'existe pas
                        $stmt = $pdo->prepare("INSERT INTO int_tags (name) VALUES (:name)");
                        $stmt->execute([':name' => $tag]);
                        $id_itag = $pdo->lastInsertId();
                    }

                    // Lier le tag à l'annonce
                    $stmt = $pdo->prepare("INSERT INTO have_itags (id_itag, id_internship) VALUES (:id_itag, :id_internship)");
                    $stmt->execute([
                        ':id_itag' => $id_itag,
                        ':id_internship' => $id_internship
                    ]);
                }
            }
        }

        return $response->withHeader('Location', '/internships')->withStatus(302);
    });

    $app->get('/internships/apply/{id}', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $view = Twig::fromRequest($request);
        $id_internship = (int)$args['id'];

        $stmt = $pdo->prepare("SELECT * FROM internships WHERE id_internship = :id");
        $stmt->execute([':id' => $id_internship]);
        $internship = $stmt->fetch();

        if (!$internship) {
            return $response->withHeader('Location', '/internships')->withStatus(404);
        }

        return $view->render($response, 'apply_internship.twig', ['internship' => $internship]);
    });

    $app->post('/internships/apply/{id}', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $id_internship = (int)$args['id'];

        // Vérification de la session utilisateur
        if (!isset($_SESSION['user_id'])) {
            $_SESSION['flash_error'] = "Vous devez être connecté pour postuler.";
            return $response->withHeader('Location', '/login')->withStatus(302);
        }
        $user_id = $_SESSION['user_id'];

        $data = $request->getParsedBody();
        $upload_dir = __DIR__ . '/../public/uploads/';
        $cv_path = null;

        // Gestion de l'upload du CV
        if (!empty($_FILES['cv']['tmp_name'])) {
            $file = $_FILES['cv'];
            $mime = mime_content_type($file['tmp_name']);

            if (str_starts_with($mime, 'application/pdf')) {
                $filename = uniqid('cv_') . '.pdf';
                $target_path = $upload_dir . $filename;

                if (move_uploaded_file($file['tmp_name'], $target_path)) {
                    $cv_path = '/uploads/' . $filename;
                }
            }
        }

        if (!$cv_path) {
            $_SESSION['flash_error'] = "Erreur lors de l'upload du CV. Veuillez réessayer.";
            return $response->withHeader('Location', '/internships/apply/' . $id_internship)->withStatus(400);
        }

        try {
            // Enregistrement de la candidature dans la table `candidate`
            $stmt = $pdo->prepare("
                INSERT INTO candidate (id_internship, id_user, CV_Path, Motiv, EtatCandidature)
                VALUES (:id_internship, :id_user, :cv_path, :motivation_letter, :etat_candidature)
            ");
            $stmt->execute([
                ':id_internship' => $id_internship,
                ':id_user' => $user_id,
                ':cv_path' => $cv_path,
                ':motivation_letter' => $data['motivation_letter'],
                ':etat_candidature' => 0 // 0 = En attente
            ]);

            $_SESSION['flash_success'] = "Votre candidature a été envoyée avec succès.";
            return $response->withHeader('Location', '/internships')->withStatus(302);
        } catch (PDOException $e) {
            error_log("Erreur SQL : " . $e->getMessage());
            $_SESSION['flash_error'] = "Une erreur est survenue lors de l'enregistrement de votre candidature.";
            return $response->withHeader('Location', '/internships/apply/' . $id_internship)->withStatus(500);
        }
    });

    // Route POST : Ajouter une offre à la wishlist
    $app->post('/internships/{id}/like', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $id_internship = (int)$args['id'];

        // Vérification de la session utilisateur
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        // Journaliser l'état de la session avant l'opération
        error_log("DEBUG: Session avant l'ajout aux favoris : " . json_encode($_SESSION));

        if (!isset($_SESSION['user_id'])) {
            $_SESSION['flash_error'] = "Vous devez être connecté pour ajouter une offre à vos favoris.";
            return $response->withHeader('Location', '/login')->withStatus(302);
        }
        $id_user = $_SESSION['user_id'];

        try {
            $stmt = $pdo->prepare("SELECT * FROM favorite WHERE id_user = :id_user AND id_internship = :id_internship");
            $stmt->execute([':id_user' => $id_user, ':id_internship' => $id_internship]);
            $favorite = $stmt->fetch();

            if ($favorite) {
                $_SESSION['flash_error'] = "Cette offre est déjà dans vos favoris.";
            } else {
                $stmt = $pdo->prepare("INSERT INTO favorite (id_user, id_internship) VALUES (:id_user, :id_internship)");
                $stmt->execute([':id_user' => $id_user, ':id_internship' => $id_internship]);
                $_SESSION['flash_success'] = "Offre ajoutée à vos favoris.";
            }
        } catch (PDOException $e) {
            error_log("Erreur SQL : " . $e->getMessage());
            $_SESSION['flash_error'] = "Une erreur est survenue lors de l'ajout aux favoris.";
        }

        // Journaliser l'état de la session après l'opération
        error_log("DEBUG: Session après l'ajout aux favoris : " . json_encode($_SESSION));

        return $response->withHeader('Location', '/internships')->withStatus(302);
    });

    // Route POST : Supprimer une offre de la wishlist
    $app->post('/internships/{id}/unlike', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $id_internship = (int)$args['id'];

        if (!isset($_SESSION['user_id'])) {
            $_SESSION['flash_error'] = "Vous devez être connecté pour retirer une offre de vos favoris.";
            return $response->withHeader('Location', '/login')->withStatus(302);
        }
        $id_user = $_SESSION['user_id'];

        try {
            $stmt = $pdo->prepare("DELETE FROM favorite WHERE id_user = :id_user AND id_internship = :id_internship");
            $stmt->execute([':id_user' => $id_user, ':id_internship' => $id_internship]);
            $_SESSION['flash_success'] = "Offre retirée de vos favoris.";
        } catch (PDOException $e) {
            error_log("Erreur SQL : " . $e->getMessage());
            $_SESSION['flash_error'] = "Une erreur est survenue lors de la suppression des favoris.";
        }

        return $response->withHeader('Location', '/internships')->withStatus(302);
    });

    // Route GET : Afficher les offres likées par l'utilisateur
    $app->get('/wishlist', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $view = Twig::fromRequest($request);

        if (!isset($_SESSION['user_id'])) {
            $_SESSION['flash_error'] = "Vous devez être connecté pour voir vos favoris.";
            return $response->withHeader('Location', '/login')->withStatus(302);
        }
        $id_user = $_SESSION['user_id'];

        $stmt = $pdo->prepare("
            SELECT internships.*, companies.name AS company_name 
            FROM favorite
            JOIN internships ON favorite.id_internship = internships.id_internship
            JOIN companies ON internships.id_company = companies.id_company
            WHERE favorite.id_user = :id_user
            ORDER BY favorite.id_internship DESC
        ");
        $stmt->execute([':id_user' => $id_user]);
        $favorites = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return $view->render($response, 'wishlist.twig', ['favorites' => $favorites]);
    });

    $app->get('/applications', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $view = Twig::fromRequest($request);

        if (!isset($_SESSION['user_id'])) {
            $_SESSION['flash_error'] = "Vous devez être connecté pour voir vos candidatures.";
            return $response->withHeader('Location', '/login')->withStatus(302);
        }
        $id_user = $_SESSION['user_id'];

        $stmt = $pdo->prepare("
            SELECT internships.*, companies.name AS company_name, candidate.Motiv, candidate.EtatCandidature 
            FROM candidate
            JOIN internships ON candidate.id_internship = internships.id_internship
            JOIN companies ON internships.id_company = companies.id_company
            WHERE candidate.id_user = :id_user
            ORDER BY internships.bdate DESC
        ");
        $stmt->execute([':id_user' => $id_user]);
        $applications = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return $view->render($response, 'applications.twig', ['applications' => $applications]);
    });

    $app->get('/internships/detail/{id}', function (Request $request, Response $response, $args) {
        $pdo = $this->get(PDO::class);
        $view = Twig::fromRequest($request);
        $id_internship = (int)$args['id'];

        // Récupérer le rôle de l'utilisateur
        $role = null;
        if (isset($_SESSION['token'])) {
            $role = getUserRole($pdo, $_SESSION['token']);
        }

        $stmt = $pdo->prepare("
            SELECT internships.*, companies.name AS company_name 
            FROM internships 
            JOIN companies ON internships.id_company = companies.id_company 
            WHERE internships.id_internship = :id
        ");

        $stmt->execute([':id' => $id_internship]);
        $internship = $stmt->fetch(PDO::FETCH_ASSOC);

        // Si le rôle est 2 et le statut est 0, rediriger vers la liste des stages
        if ($role === 2 && $internship['status'] == 0) {
            return $response->withHeader('Location', '/internships')->withStatus(302);
        }

        if (!$internship) {
            return $response->withHeader('Location', '/internships')->withStatus(404);
        }

        $stmtTags = $pdo->prepare("
            SELECT int_tags.name 
            FROM have_itags 
            JOIN int_tags ON have_itags.id_itag = int_tags.id_itag 
            WHERE have_itags.id_internship = :id_internship
        ");
        $stmtTags->execute([':id_internship' => $id_internship]);
        $internship['tags'] = $stmtTags->fetchAll(PDO::FETCH_COLUMN);

        // Vérifier si l'utilisateur a ajouté ce stage à ses favoris
        $user_id = $_SESSION['user_id'] ?? null;
        if ($user_id) {
            $stmtFavorite = $pdo->prepare("
                SELECT 1 
                FROM favorite 
                WHERE id_user = :id_user AND id_internship = :id_internship
            ");
            $stmtFavorite->execute([
                ':id_user' => $user_id,
                ':id_internship' => $id_internship
            ]);
            $internship['is_favorite'] = (bool) $stmtFavorite->fetchColumn();
        } else {
            $internship['is_favorite'] = false;
        }

        // Compter le nombre d'ajouts à la wishlist
        $stmtWishlistCount = $pdo->prepare("
            SELECT COUNT(*) 
            FROM favorite 
            WHERE id_internship = :id_internship
        ");
        $stmtWishlistCount->execute([':id_internship' => $id_internship]);
        $wishlistCount = $stmtWishlistCount->fetchColumn();

        return $view->render($response, 'internship_detail.twig', [
            'internship' => $internship,
            'wishlist_count' => $wishlistCount,
            'role' => $role // Injecter le rôle dans Twig
        ]);
    });

    // Exemple d'utilisation de la fonction getUserRole dans une route
    $app->get('/test-role', function (Request $request, Response $response) {
        $pdo = $this->get(PDO::class);

        if (!isset($_SESSION['token'])) {
            $response->getBody()->write("Token non défini dans la session.");
            return $response->withStatus(400);
        }

        $role = getUserRole($pdo, $_SESSION['token']);
        if ($role !== null) {
            $response->getBody()->write("Le rôle de l'utilisateur est : $role");
        } else {
            $response->getBody()->write("Utilisateur non trouvé ou rôle non défini.");
        }

        return $response;
    });
};
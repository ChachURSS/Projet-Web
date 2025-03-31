<?php

return function (\DI\ContainerBuilder $containerBuilder) {
    $containerBuilder->addDefinitions([
        'db' => [
            'host' => 'localhost',
            'dbname' => 'easy_stage_web',
            'user' => 'root',
            'pass' => 'password'
        ],
        'displayErrorDetails' => true
    ]);
};

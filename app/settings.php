<?php

return function (\DI\ContainerBuilder $containerBuilder) {
    $containerBuilder->addDefinitions([
        'db' => [
            'host' => 'localhost',
            'dbname' => 'es_datas',
            'user' => 'root',
            'pass' => 'password'
        ],
        'displayErrorDetails' => true
    ]);
};

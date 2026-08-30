<?php

$finder = PhpCsFixer\Finder::create()->in(['src', 'tests']);

return (new PhpCsFixer\Config())
    ->setRules(['@Symfony' => true])
    ->setRiskyAllowed(true)
    ->setFinder($finder);

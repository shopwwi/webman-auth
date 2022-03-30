<?php

namespace app\command;

use Shopwwi\WebmanAuth\Facade\Str;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Output\OutputInterface;


class ShopwwiAuthCommand extends Command
{
    protected static $defaultName = 'shopwwi:auth';
    protected static $defaultDescription = 'shopwwi auth';

    /**
     * @return void
     */
    protected function configure()
    {
        $this->addArgument('name', InputArgument::OPTIONAL, 'Name description');
    }

    /**
     * @param InputInterface $input
     * @param OutputInterface $output
     * @return int
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $name = $input->getArgument('name');
        $output->writeln('生成jwtKey 开始');
        $key = Str::random(64);
        file_put_contents(base_path()."/config/plugin/shopwwi/auth/app.php", str_replace(
            "'access_secret_key' => '".config('plugin.shopwwi.auth.app.jwt.access_secret_key')."'",
            "'access_secret_key' => '".$key."'",
            file_get_contents(base_path()."/config/plugin/shopwwi/auth/app.php")
        ));
        file_put_contents(base_path()."/config/plugin/shopwwi/auth/app.php", str_replace(
            "'refresh_secret_key' => '".config('plugin.shopwwi.auth.app.jwt.refresh_secret_key')."'",
            "'refresh_secret_key' => '".$key."'",
            file_get_contents(base_path()."/config/plugin/shopwwi/auth/app.php")
        ));
        $output->writeln('生成jwtKey 结束'.$key);
        return self::SUCCESS;
    }

}

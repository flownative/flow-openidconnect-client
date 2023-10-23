<?php
namespace Flownative\OpenIdConnect\Client\Command;

use Doctrine\ORM\EntityManagerInterface;
use Flownative\OpenIdConnect\Client\OpenIdConnectClient;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\GuzzleException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Cli\CommandController;

final class OidcCommandController extends CommandController
{
    /**
     * @var EntityManagerInterface
     */
    protected $entityManager;

    /**
     * @Flow\InjectConfiguration
     * @var array
     */
    protected $settings;

    /**
     * @param EntityManagerInterface $entityManager
     * @return void
     */
    public function injectEntityManager(EntityManagerInterface $entityManager): void
    {
        $this->entityManager = $entityManager;
    }

    /**
     * Discover OIDC configuration
     *
     * This command connects with the /.well-known/openid-configuration endpoint of an OIDC
     * service configured via Flow settings and retrieves information about endpoints,
     * capabilities and further information. The retrieved data is displayed in a table.
     *
     * @param string|null $serviceName The service name, as it was configured via Flow settings
     * @return void
     */
    public function discoverCommand(string $serviceName = null): void
    {
        if (empty($this->settings['services'])) {
            $this->outputLine('<error>There are no services configured in the Flow settings</error>');
            exit(1);
        }
        if ($serviceName === null) {
            if (count($this->settings['services']) > 1) {
                $this->outputLine('<error>You must specify a service with --service-name, because multiple services are available</error>');
                $this->outputLine('Use one of the following service names: ' . implode(', ', array_keys($this->settings['services'])));
                exit(1);
            }
            $serviceName = array_key_first($this->settings['services']);
        }

        if (!isset($this->settings['services'][$serviceName])) {
            $this->outputLine('<error>Unknown service "%s".</error>', [$serviceName]);
            exit(1);
        }
        if (!isset($this->settings['services'][$serviceName]['options']['discoveryUri']) || empty($this->settings['services'][$serviceName]['options']['discoveryUri'])) {
            $this->outputLine('<error>Missing option "discoveryUri" for service "%s".</error>', [$serviceName]);
            exit(1);
        }

        $httpClient = new HttpClient();

        try {
            $response = $httpClient->request('GET', $this->settings['services'][$serviceName]['options']['discoveryUri']);
        } catch (GuzzleException $e) {
            $this->outputLine('<error>Failed discovering options at via "%s:" %s</error>', [$this->settings['services'][$serviceName]['options']['discoveryUri'], $e->getMessage()]);
            exit(1);
        }

        $discoveredOptions = \GuzzleHttp\json_decode($response->getBody()->getContents(), true);
        if (!is_array($discoveredOptions)) {
            $this->outputLine('<error>Discovery endpoint returned invalid response</error>');
            exit(1);
        }

        $rows = [];
        foreach ($discoveredOptions as $optionName => $optionValue) {
            $rows[] = [
                $optionName,
                !is_string($optionValue) ? var_export($optionValue, true) : $optionValue
            ];
        }

        $this->output->outputTable($rows, ['Option', 'Value']);
    }

    /**
     * @param string $serviceName
     */
    public function getAccessTokenCommand(string $serviceName): void
    {
        $openIdConnectClient = new OpenIdConnectClient($serviceName);

        $additionalParameters = $this->settings['services'][$serviceName]['options']['additionalParameters'] ?? [];
        try {
            $accessToken = $openIdConnectClient->getAccessToken(
                $serviceName,
                $this->settings['services'][$serviceName]['options']['clientId'],
                $this->settings['services'][$serviceName]['options']['clientSecret'],
                'profile name',
                $additionalParameters
            );
        } catch (IdentityProviderException $e) {
            $this->outputLine('<error>%s: "%s"</error>', [$e->getMessage(), $e->getResponseBody()['error_description'] ?? '']);
            exit (1);
        } catch (\Exception $e) {
            $this->outputLine('<error>%s</error>', [$e->getMessage()]);
            exit (1);
        }

        $this->outputLine($accessToken->getToken());
    }
}

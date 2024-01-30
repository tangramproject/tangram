// Tangram by Matthew Hellyer is licensed under CC BY-NC-ND 4.0.
// To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Autofac;
using AutofacSerilogIntegration;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using TangramXtgm.Cryptography;
using TangramXtgm.Helper;
using TangramXtgm.Ledger;
using TangramXtgm.Models;
using TangramXtgm.Network;
using TangramXtgm.Persistence;
using TangramXtgm.Services;
using TangramXtgm.Wallet;

namespace TangramXtgm.Extensions;

/// <summary>
/// Extension methods for configuring the application services.
/// </summary>
public static class AppExtensions
{
    /// <summary>
    /// Adds Serilog as the logging provider for Autofac container.
    /// </summary>
    /// <param name="builder">The Autofac container builder.</param>
    public static void AddSerilog(this ContainerBuilder builder)
    {
        builder.RegisterLogger();
    }

    /// <summary>
    /// Adds the SystemCore to the ContainerBuilder.
    /// </summary>
    /// <param name="builder">The ContainerBuilder.</param>
    /// <param name="configuration">The configuration.</param>
    /// <returns>The ContainerBuilder.</returns>
    public static ContainerBuilder AddSystemCore(this ContainerBuilder builder, IConfiguration configuration)
    {
        builder.Register(c =>
        {
            var remoteNodes = configuration.GetSection("Node:Network:SeedList").GetChildren().ToArray();
            var node = new Node
            {

                EndPoint = new IPEndPoint(IPAddress.Parse(configuration["Node:Network:PublicIPAddress"]), 0),
                Name = configuration["Node:Name"],
                Data =
                    new Data
                    {
                        RocksDb = configuration["Node:Data:RocksDb"],
                        KeysProtectionPath = configuration["Node:Data:KeysProtectionPath"]
                    },
                Network = new Models.Network
                {
                    Environment = configuration["Node:Network:Environment"],
                    CertificateMode = configuration["Node:Network:CertificateMode"],
                    PublicIPAddress = configuration["Node:Network:PublicIPAddress"],
                    HttpPort = Convert.ToInt32(configuration["Node:Network:HttpPort"]),
                    HttpsPort = Convert.ToInt32(configuration["Node:Network:HttpsPort"]),
                    P2P =
                        new P2P
                        {
                            TcpPort = Convert.ToInt32(configuration["Node:Network:P2P:TcpPort"]),
                            WsPort = Convert.ToInt32(configuration["Node:Network:P2P:WsPort"])
                        },
                    SeedList = new List<string>(remoteNodes.Length),
                    X509Certificate =
                        new Models.X509Certificate
                        {
                            Password = configuration["Node:Network:X509Certificate:Password"],
                            Thumbprint = configuration["Node:Network:X509Certificate:Thumbprint"],
                            CertPath = configuration["Node:Network:X509Certificate:CertPath"]
                        },
                    MemoryPoolTransactionRateLimit = new TransactionLeakRateConfigurationOption
                    {
                        LeakRate =
                            Convert.ToInt32(
                                configuration["Node:Network:MemoryPoolTransactionRateLimit:LeakRate"]),
                        MemoryPoolMaxTransactions =
                            Convert.ToInt32(configuration[
                                "Node:Network:MemoryPoolTransactionRateLimit:MemoryPoolMaxTransactions"]),
                        LeakRateNumberOfSeconds = Convert.ToInt32(
                            configuration[
                                "Node:Network:MemoryPoolTransactionRateLimit:LeakRateNumberOfSeconds"])
                    },
                    SigningKeyRingName = configuration["Node:Network:SigningKeyRingName"],
                    SyncTrailStop = Convert.ToInt16(configuration["Node:Network:SyncTrailStop"])
                },
                Staking = new Staking
                {
                    MaxTransactionsPerBlock =
                        Convert.ToInt32(configuration["Node:Staking:MaxTransactionsPerBlock"]),
                    MaxTransactionSizePerBlock =
                        Convert.ToInt32(configuration["Node:Staking:MaxTransactionSizePerBlock"])
                }
            };
            foreach (var selection in remoteNodes.WithIndex())
            {
                try
                {
                    var endpoint = Util.GetIpEndPoint(selection.item.Value);
                    var endpointFromHost = Util.GetIpEndpointFromHostPort(endpoint.Address.ToString(), endpoint.Port);
                    node.Network.SeedList.Add($"{endpointFromHost.Address.ToString()}:{endpointFromHost.Port}");
                }
                catch (Exception)
                {
                    // Ignore
                }
            }

            var systemCore = new SystemCore(c.Resolve<IHostApplicationLifetime>(),
                c.Resolve<IServiceScopeFactory>(), node, c.Resolve<ILogger>());
            return systemCore;
        }).As<ISystemCore>().SingleInstance();
        return builder;
    }

    /// <summary>
    /// Adds the PeerDiscovery service to the Autofac container.
    /// </summary>
    /// <param name="builder">The ContainerBuilder instance.</param>
    /// <returns>The modified ContainerBuilder instance.</returns>
    public static ContainerBuilder AddPeerDiscovery(this ContainerBuilder builder)
    {
        builder.RegisterType<PeerDiscovery>().As<IPeerDiscovery>().SingleInstance();
        return builder;
    }

    /// <summary>
    /// Registers the P2PDeviceApi and P2PDevice types with the ContainerBuilder.
    /// </summary>
    /// <param name="builder">The ContainerBuilder instance.</param>
    /// <returns>The ContainerBuilder instance.</returns>
    public static ContainerBuilder AddP2PDevice(this ContainerBuilder builder)
    {
        builder.RegisterType<P2PDeviceApi>().As<IP2PDeviceApi>().InstancePerDependency();
        builder.RegisterType<P2PDevice>().As<IP2PDevice>().SingleInstance();
        return builder;
    }

    /// <summary>
    /// Adds the Broadcast implementation of IBroadcast to the ContainerBuilder.
    /// </summary>
    /// <param name="builder">The ContainerBuilder instance.</param>
    /// <returns>The updated ContainerBuilder instance.</returns>
    public static ContainerBuilder AddBroadcast(this ContainerBuilder builder)
    {
        builder.RegisterType<Broadcast>().As<IBroadcast>().InstancePerDependency();
        return builder;
    }

    /// <summary>
    /// Adds a long-running service to the container.
    /// </summary>
    /// <param name="builder">The ContainerBuilder instance.</param>
    /// <returns>The ContainerBuilder instance with the long-running service added.</returns>
    public static ContainerBuilder AddLongRunningService(this ContainerBuilder builder)
    {
        builder.RegisterType<LongRunningService>().As<IHostedService>().InstancePerDependency();
        builder.RegisterType<BackgroundWorkerQueue>().As<IBackgroundWorkerQueue>().SingleInstance();
        return builder;
    }

    /// <summary>
    /// Adds a memory pool to the ContainerBuilder.
    /// </summary>
    /// <param name="builder">The ContainerBuilder instance.</param>
    /// <returns>The updated ContainerBuilder instance.</returns>
    public static ContainerBuilder AddMemoryPool(this ContainerBuilder builder)
    {
        builder.RegisterType<MemoryPool>().As<IMemoryPool>().SingleInstance();
        return builder;
    }

    /// <summary>
    /// Adds the PPoS implementation to the container. </summary>
    /// <param name="builder">The ContainerBuilder to add the PPoS implementation to.</param>
    /// <returns>The modified ContainerBuilder.</returns>
    public static ContainerBuilder AddPPoS(this ContainerBuilder builder)
    {
        builder.RegisterType<PPoS>().As<IPPoS>().SingleInstance();
        return builder;
    }

    /// <summary>
    /// Registers a unit of work implementation in the Autofac container.
    /// </summary>
    /// <param name="builder">The Autofac container builder.</param>
    /// <param name="configuration">The configuration object used to retrieve settings.</param>
    /// <returns>The modified container builder.</returns>
    public static ContainerBuilder AddUnitOfWork(this ContainerBuilder builder, IConfiguration configuration)
    {
        builder.Register(c =>
        {
            UnitOfWork unitOfWork = new(configuration["Node:Data:RocksDb"], c.Resolve<ILogger>());
            return unitOfWork;
        }).As<IUnitOfWork>().SingleInstance();
        return builder;
    }

    /// <summary>
    /// Adds the graph registration to the ContainerBuilder.
    /// </summary>
    /// <param name="builder">The ContainerBuilder instance to add the graph registration to.</param>
    /// <returns>The same ContainerBuilder instance with the added graph registration.</returns>
    public static ContainerBuilder AddGraph(this ContainerBuilder builder)
    {
        builder.RegisterType<Graph>().As<IGraph>().SingleInstance();
        return builder;
    }

    /// <summary>
    /// Adds a validator to the ContainerBuilder.
    /// </summary>
    /// <param name="builder">The ContainerBuilder instance.</param>
    /// <returns>The updated ContainerBuilder instance.</returns>
    public static ContainerBuilder AddValidator(this ContainerBuilder builder)
    {
        builder.RegisterType<Validator>().As<IValidator>().InstancePerDependency();
        return builder;
    }

    /// <summary>
    /// Adds the Crypto component to the Autofac container.
    /// </summary>
    /// <param name="builder">The Autofac container builder.</param>
    /// <returns>The updated Autofac container builder.</returns>
    public static ContainerBuilder AddCrypto(this ContainerBuilder builder)
    {
        builder.RegisterType<Crypto>().As<ICrypto>().InstancePerDependency();
        return builder;
    }

    /// <summary>
    /// Adds data keys protection to the specified service collection using the provided configuration.
    /// </summary>
    /// <param name="services">The service collection to modify.</param>
    /// <param name="configuration">The configuration containing the necessary options.</param>
    /// <returns>The modified service collection.</returns>
    public static IServiceCollection AddDataKeysProtection(this IServiceCollection services,
        IConfiguration configuration)
    {
        X509Certificate2 certificate;
        if (!string.IsNullOrEmpty(configuration["Node:Network:X509Certificate:CertPath"]) &&
            !string.IsNullOrEmpty(configuration["Node:Network:X509Certificate:Password"]))
            certificate = new X509Certificate2(configuration["Node:Network:X509Certificate:CertPath"],
                configuration["Node:Network:X509Certificate:Password"]);
        else
            certificate =
                new CertificateResolver().ResolveCertificate(configuration["Node:Network:X509Certificate:Thumbprint"]);

        if (certificate != null)
            services.AddDataProtection()
                .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(Util.EntryAssemblyPath(),
                    configuration["Node:Data:KeysProtectionPath"]))).ProtectKeysWithCertificate(certificate)
                .SetApplicationName(configuration["Node:Name"]).SetDefaultKeyLifetime(TimeSpan.FromDays(3650));
        return services;
    }

    /// <summary>
    /// Registers the Sync type as ISync in the container and configures
    /// it to be a singleton, allowing synchronous operations.
    /// </summary>
    /// <param name="builder">
    /// The ContainerBuilder used to build the container.
    /// </param>
    /// <returns>
    /// The ContainerBuilder instance.
    /// </returns>
    public static ContainerBuilder AddSync(this ContainerBuilder builder)
    {
        builder.RegisterType<Sync>().As<ISync>().SingleInstance();
        return builder;
    }

    /// <summary>
    /// Registers the NodeMonitorService implementation and its dependencies in the Autofac container.
    /// </summary>
    /// <param name="builder">The Autofac container builder.</param>
    /// <param name="configuration">The configuration object.</param>
    /// <returns>The modified Autofac container builder.</returns>
    public static ContainerBuilder AddNodeMonitorService(this ContainerBuilder builder,
        IConfiguration configuration)
    {
        builder.Register(c =>
        {
            var nodeMonitorConfigurationOptions = new NodeMonitorConfigurationOptions();
            configuration.Bind(NodeMonitorConfigurationOptions.ConfigurationSectionName,
                nodeMonitorConfigurationOptions);
            var nodeMonitorProvider =
                new NodeMonitor(nodeMonitorConfigurationOptions, c.Resolve<ILogger>());
            return nodeMonitorProvider;
        }).As<INodeMonitor>().InstancePerLifetimeScope();
        builder.RegisterType<NodeMonitorService>().As<IHostedService>();
        return builder;
    }

    /// <summary>
    /// Registers the NodeWallet implementation of INodeWallet with the Autofac container.
    /// </summary>
    /// <param name="builder">The Autofac container builder.</param>
    /// <returns>The Autofac container builder with the NodeWallet registration.</returns>
    public static ContainerBuilder AddNodeWallet(this ContainerBuilder builder)
    {
        builder.RegisterType<NodeWallet>().As<INodeWallet>().InstancePerDependency();
        return builder;
    }

    /// <summary>
    /// Registers the WalletSession implementation as a single instance of the IWalletSession interface in the given ContainerBuilder.
    /// </summary>
    /// <param name="builder">The ContainerBuilder instance to register the WalletSession with.</param>
    /// <returns>The original ContainerBuilder instance.</returns>
    public static ContainerBuilder AddNodeWalletSession(this ContainerBuilder builder)
    {
        builder.RegisterType<WalletSession>().As<IWalletSession>().SingleInstance();
        return builder;
    }
}
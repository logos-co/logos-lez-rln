#ifndef I_MIX_SIMULATION_MODULE_H
#define I_MIX_SIMULATION_MODULE_H

#include <core/interface.h>

class IMixSimulationModule {
public:
    virtual ~IMixSimulationModule() = default;
    virtual void initLogos(LogosAPI* logosApiInstance) = 0;

    /// Start the full simulation sequence from a single JSON config blob.
    /// Config schema:
    /// {
    ///   "delivery": { ... WakuNodeConf fields ... },
    ///   "contentTopic": "/logos/1/test/proto",
    ///   "rln": { "configAccountId": "...", "leafIndex": 0 },
    ///   "simulation": {
    ///     "peerDiscoveryDelayMs": 15000,
    ///     "messageCount": 10,
    ///     "messageDelayMs": 2000,
    ///     "payload": "test message"
    ///   }
    /// }
    virtual bool start(const QString& configJson) = 0;

    /// Stop the simulation and clean up timers
    virtual void stop() = 0;
};

#define IMixSimulationModule_iid "org.logos.imixsimulationmodule"
Q_DECLARE_INTERFACE(IMixSimulationModule, IMixSimulationModule_iid)

#endif
